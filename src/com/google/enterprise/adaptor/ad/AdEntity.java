package com.google.enterprise.adaptor.ad;

import com.google.common.annotations.VisibleForTesting;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/** Representation of a single user or group from Active Directory. */
public class AdEntity {
  private static final Logger log =
      Logger.getLogger(AdEntity.class.getName());

  private String dn;
  private String sAMAccountName;
  private String userPrincipalName;
  private String primaryGroupId;
  private String sid;
  private String objectGUID;
  private Set<String> members;
  private long uSNChanged;
  private boolean wellKnown;
  private boolean allMembershipsRetrieved;
  private long userAccountControl;  // determines whether user/group is disabled
  private final Pattern attrMemberPattern =
      Pattern.compile("member;range=[0-9]+-.*", Pattern.CASE_INSENSITIVE);

  private Object getAttribute(Attributes attributes, String name)
      throws NamingException {
    Attribute attribute = attributes.get(name);
    if (attribute != null) {
      return attribute.get(0);
    } else {
      return null;
    }
  }

  private Attribute getMemberAttr(Attributes attrs) throws NamingException {
    allMembershipsRetrieved = true;
    Attribute member = attrs.get("member");
    if (member != null && member.size() != 0) {
      return member;
    }

    NamingEnumeration<String> ids = attrs.getIDs();
    while (ids.hasMore()) {
      String id = ids.next();
      if (attrMemberPattern.matcher(id).matches()) {
        allMembershipsRetrieved = id.endsWith("*");
        return attrs.get(id);
      }
    }

    return null;
  }

  /**
   * Standard constructor for AdEntity. The instance is created from LDAP
   * search result.
   * @param searchResult searchResult to create the object from
   * @throws NamingException
   */
  public AdEntity(SearchResult searchResult) throws NamingException {
    dn = searchResult.getNameInNamespace();
    wellKnown = false;
    Attributes attrs = searchResult.getAttributes();
    sAMAccountName = (String) getAttribute(attrs, "sAMAccountName");
    objectGUID = getTextGuid((byte[]) getAttribute(attrs, "objectGUID;binary"));
    sid = getTextSid((byte[]) getAttribute(attrs, "objectSid;binary"));
    String s = (String) getAttribute(attrs, "uSNChanged");
    if (s != null) {
      uSNChanged = Long.parseLong(s);
    }
    primaryGroupId = (String) getAttribute(attrs, "primaryGroupId");
    userPrincipalName = (String) getAttribute(attrs, "userPrincipalName");
    s = (String) getAttribute(attrs, "userAccountControl");
    if (s == null) {
      userAccountControl = 0; // not disabled - any value where value & 2 == 0
    } else {
      userAccountControl = Long.parseLong(s);
    }

    members = new HashSet<String>();
    if (isGroup()) {
      Attribute member = getMemberAttr(attrs);
      if (member != null) {
        for (int i = 0; i < member.size(); ++i) {
          members.add(member.get(i).toString());
        }
      }
    }
  }

  /**
   * Constructor to be used only for creating well known group identities
   * @param sid identifier of the object, this will be used as objectGUID as
   *        well to ensure uniqueness in the database
   * @param dn distinguished name of the object
   */
  public AdEntity(String sid, String dn) {
    this.sid = sid;
    this.dn = dn;
    members = new HashSet<String>();
    objectGUID = sid;
    sAMAccountName = getCommonName();
    wellKnown = true;
  }

  /**
   * Constructor to be used only for creating well known user identities
   * @param sid identifier of the object, this will be used as objectGUID as
   *        well to ensure uniqueness in the database
   * @param dn distinguished name of the object
   * @param primaryGroupId user's primary group -- non-null implies user
   */
  public AdEntity(String sid, String dn, String primaryGroupId,
      String sAMAccountName) {
    this.sid = sid;
    this.dn = dn;
    this.primaryGroupId = primaryGroupId;
    this.sAMAccountName = sAMAccountName;
    members = new HashSet<String>();
    objectGUID = sid;
    wellKnown = true;
  }

  /**
   * Appends additional memberships from search result
   * @param searchResult which contains additional groups
   * @return number of groups found
   * @throws NamingException
   */
  public int appendGroups(SearchResult searchResult)
      throws NamingException {
    Attribute member = getMemberAttr(searchResult.getAttributes());
    if (member != null) {
      for (int i = 0; i < member.size(); ++i) {
        members.add(member.get(i).toString());
      }
      return member.size();
    } else {
      return 0;
    }
  }

  /**
   * Returns commonName for the given user/group while making LDAP search query
   * to get all parents groups for a given group we need to retrieve the DN
   * name for a group.
   * @return group DN from group name.
   */
  public String getCommonName() {
    // LDAP queries return escaped commas to avoid ambiguity, find first not
    // escaped comma
    int comma = dn.indexOf(",");
    while (comma > 0 && dn.charAt(comma - 1) == '\\') {
      comma = dn.indexOf(",", comma + 1);
    }
    String tmpGroupName = dn.substring(0, comma > 0 ? comma : dn.length());
    tmpGroupName = tmpGroupName.substring(tmpGroupName.indexOf('=') + 1);
    tmpGroupName = tmpGroupName.replace("\\", "");
    return tmpGroupName;
  }

  /**
   * Parses the binary SID retrieved from LDAP and converts to textual
   * representation. Text version is used to avoid dealing with different BLOB
   * types between databases.
   * @param objectSid binary array with the SID
   * @return textual representation of SID or null
   * @see <a href="https://msdn.microsoft.com/en-us/library/gg465313.aspx">
   *     SID Packet Representation</a>
   */
  public static String getTextSid(byte[] objectSid) {
    if (objectSid == null) {
      return null;
    }
    StringBuilder strSID = new StringBuilder("S-");
    // read the Revision
    long version = objectSid[0] & 0xFF;
    strSID.append(Long.toString(version));

    // read the SubAuthorityCount
    long count = objectSid[1] & 0xFF;

    // the IdentifierAuthority is stored as big-endian 48 bit integer
    long authority = objectSid[2] & 0xFF;
    for (int i = 1; i < 6; i++) {
      authority <<= 8;
      authority += objectSid[2 + i] & 0xFF;
    }
    strSID.append('-').append(Long.toString(authority));

    long rid;
    // each SubAuthority is stored as little-endian 32-bit integer
    for (int j = 0; j < count; j++) {
      rid = objectSid[11 + (j * 4)] & 0xFF;
      for (int k = 1; k < 4; k++) {
        rid <<= 8;
        rid += objectSid[11 - k + (j * 4)] & 0xFF;
      }
      strSID.append('-').append(Long.toString(rid));
    }
    return strSID.toString();
  }

  /**
   * Parses the binary GUID retrieved from LDAP and converts to textual
   * representation. Text version is used to avoid dealing with different
   * BLOB types between databases.
   * @param binaryGuid
   * @return string containing the GUID
   */
  public static String getTextGuid(byte[] binaryGuid) {
    StringBuilder sb = new StringBuilder("0x");
    for (byte b : binaryGuid) {
      sb.append(Integer.toHexString(b & 0xFF));
    }
    return sb.toString();
  }

  /**
   * @return the members
   */
  public Set<String> getMembers() {
    return members;
  }

  @Override
  public String toString() {
    SBS result = new SBS();
    result.append("dn", dn);
    result.append("members", members);
    result.append("sAMAccountName", sAMAccountName);
    result.append("userPrincipalName", userPrincipalName);
    result.append("primaryGroupId", primaryGroupId);
    result.append("sid", sid);
    result.append("objectGUID", objectGUID);
    result.append("sid", sid);
    result.append("uSNChanged", uSNChanged);
    result.append("userAccountControl", userAccountControl);
    result.append("allMembershipsRetrieved", allMembershipsRetrieved);
    return "{ " + result + "}";
  }

  /**
   * @return the dn
   */
  public String getDn() {
    return dn;
  }

  /**
   * @return sAMAccountName
   */
  public String getSAMAccountName() {
    return sAMAccountName;
  }

  /**
  * @return if current entity is group
  */
  public boolean isGroup() {
    return primaryGroupId == null;
  }

  public boolean isWellKnown() {
    return wellKnown;
  }

  /**
  * @return if current entity is disabled
  */
  public boolean isDisabled() {
    //TODO(myk): see if there's any reason to check ADS_UF_LOCKOUT [16]
    return ((userAccountControl & 2) != 0);
  }

  @VisibleForTesting
  void setUserAccountControl(long userAccountControl) {
    this.userAccountControl = userAccountControl;
  }

  /**
   * @return if we need to retrieve further memberships for this group
   */
  public boolean areAllMembershipsRetrieved() {
    return allMembershipsRetrieved;
  }

  public String getSid() {
    return sid;
  }

  public String getPrimaryGroupSid() {
    int index = sid.lastIndexOf('-') + 1;
    return sid.substring(0,  index) + primaryGroupId;
  }

  public static String parseForeignSecurityPrincipal(String dn) {
    if (!dn.toLowerCase().contains("cn=foreignsecurityprincipals,dc=")) {
      return null;
    }
    int start = dn.indexOf('=');
    int end = dn.indexOf(',');
    String sid = dn.substring(start + 1, end);
    // check for mangled or malformed security principal format
    if (!sid.matches("^S-1-[15](-[0-9]+)+$")) {
      log.fine("invalid foreign security principal [" + dn + "].");
      return null;
    }
    return sid;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AdEntity)) {
      return false;
    }
    AdEntity other = (AdEntity) o;
    return dn.equals(other.dn)
        && ((sAMAccountName == null) ? (other.sAMAccountName == null) :
            sAMAccountName.equals(other.sAMAccountName))
        && ((userPrincipalName == null) ? (other.userPrincipalName == null) :
            userPrincipalName.equals(other.userPrincipalName))
        && ((primaryGroupId == null) ? (other.primaryGroupId == null) :
            primaryGroupId.equals(other.primaryGroupId))
        && ((sid == null) ? (other.sid == null) : sid.equals(other.sid))
        && ((members == null) ? (other.members == null) :
            members.equals(other.members))
        && uSNChanged == other.uSNChanged
        && userAccountControl == other.userAccountControl;
        // note: 3 fields (objectGUID, wellKnown, and allMembershipsRetrieved)
        // are intentionally skipped - we'd need a setter method to make the
        // "golden" values correct.
  }

  @Override
  public int hashCode() {
    // same 3 fields as above are excluded here.
    return Arrays.hashCode(new Object[] {dn, sAMAccountName, userPrincipalName,
        primaryGroupId, sid, members, uSNChanged, userAccountControl});
  }

  /**
   * Used by the toString() method, to avoid repeated code
   */
  private static class SBS {
    private StringBuilder wrap = new StringBuilder();
    SBS append(String name, Object value) {
      wrap.append(name);
      if (null == value) {
        wrap.append(" is null,");
      } else {
        wrap.append(" = " + value + ",");
      }
      return this;
    }
    public String toString() {
      // eliminate trailing comma
      if (wrap.length() > 0) {
        wrap.setLength(wrap.length() - 1);
      }
      return wrap.toString();
    }
  }
}
