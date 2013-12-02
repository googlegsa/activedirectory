package com.google.enterprise.adaptor.ad;

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
   * Constructor to be used only for creating well known identities
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
   */
  public static String getTextSid(byte[] objectSid) {
    if (objectSid == null) {
      return null;
    }
    StringBuilder strSID = new StringBuilder("S-");
    long version = objectSid[0];
    strSID.append(Long.toString(version));
    long authority = objectSid[4];

    for (int i = 0; i < 4; i++) {
      authority <<= 8;
      authority += objectSid[4 + i] & 0xFF;
    }
    strSID.append('-').append(Long.toString(authority));
    long count = objectSid[2];
    count <<= 8;
    count += objectSid[1] & 0xFF;

    long rid;
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
    return dn;
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
    if (!sid.matches("^S-1-5-21(-[0-9]+)+$")) {
      log.fine("invalid foreign security principal [" + dn + "].");
      return null;
    }
    return sid;
  }
}
