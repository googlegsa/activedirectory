// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.ad;

import com.google.common.annotations.VisibleForTesting;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.AuthenticationException;
import javax.naming.AuthenticationNotSupportedException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.InterruptedNamingException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.PagedResultsResponseControl;

/** Client that talks to Active Directory. */
public class AdServer {
  private static final Logger LOGGER
      = Logger.getLogger(AdServer.class.getName());

  private LdapContext ldapContext;
  private final SearchControls searchCtls;

  // properties necessary for connection and reconnection
  private Method connectMethod;
  private final String hostName;
  private int port;
  private String principal;
  private String password;

  // retrieved properties of the Active Directory controller
  private String nETBIOSName;
  private String dn;
  private String configurationNamingContext;
  private String dsServiceName;
  private String sid;
  private long highestCommittedUSN;
  private String invocationID;
  private String dnsRoot;

  public AdServer(Method connectMethod, String hostName,
      int port, String principal, String password) {
    this(hostName, createLdapContext(connectMethod, hostName, port,
        principal, password));
    this.connectMethod = connectMethod;
    this.port = port;
    this.principal = principal;
    this.password = password;
  }

  @VisibleForTesting
  AdServer(String hostName, LdapContext ldapContext) {
    this.hostName = hostName;
    this.ldapContext = ldapContext;
    searchCtls = new SearchControls();
    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
  }

  /**
   * Called (only) by public constructor
   */
  private static LdapContext createLdapContext(Method connectMethod,
      String hostName, int port, String principal, String password) {
    Hashtable<String, String> env = new Hashtable<String, String>();
    if (null == connectMethod || null == hostName
        || null == principal || null == password) {
      throw new NullPointerException();
    }
    if ("".equals(hostName)) {
      throw new IllegalArgumentException("host needs to be non-empty");
    }
    if ("".equals(principal)) {
      throw new IllegalArgumentException("principal needs to be non-empty");
    }
    if ("".equals(password)) {
      throw new IllegalArgumentException("password needs to be non-empty");
    }

    // Use the built-in LDAP support.
    env.put(Context.INITIAL_CONTEXT_FACTORY,
        "com.sun.jndi.ldap.LdapCtxFactory");
    // Connecting to configuration naming context is very slow for crawl users
    // in large multidomain environment, which belong to thousands of groups
    // TODO: make this configurable
    env.put("com.sun.jndi.ldap.read.timeout", "90000");
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, principal);
    env.put(Context.SECURITY_CREDENTIALS, password);

    String ldapUrl = connectMethod.protocol() + hostName + ":" + port;
    LOGGER.config("LDAP provider url: " + ldapUrl);
    env.put(Context.PROVIDER_URL, ldapUrl);
    try {
      return new InitialLdapContext(env, null);
    } catch (NamingException ne) {
      throw new AssertionError(ne);
    }
  }

  @VisibleForTesting
  void recreateLdapContext() {
    ldapContext = createLdapContext(connectMethod, hostName, port, principal,
        password);
  }

  /**
   * Connects to the Active Directory server and retrieves AD configuration
   * information.
   *
   * This method is used for crawling as well as authorization of credentials
   * against Active Directory.
   */
  public void connect() throws CommunicationException, NamingException {
    Attributes attributes;
    try {
      attributes = ldapContext.getAttributes("");
    } catch (CommunicationException ce) {
      LOGGER.log(Level.FINER,
          "Reconnecting to AdServer after detecting issue", ce);
      recreateLdapContext();
      attributes = ldapContext.getAttributes("");
    }
    dn = attributes.get("defaultNamingContext").get(0).toString();
    dsServiceName = attributes.get("dsServiceName").get(0).toString();
    highestCommittedUSN = Long.parseLong(attributes.get(
        "highestCommittedUSN").get(0).toString());
    configurationNamingContext = attributes.get(
        "configurationNamingContext").get(0).toString();
  }

  public void initialize() {
    try {
      connect();
      sid = AdEntity.getTextSid((byte[]) get(
          "distinguishedName=" + dn, "objectSid;binary", dn));
      invocationID = AdEntity.getTextGuid((byte[]) get(
          "distinguishedName=" + dsServiceName,
          "invocationID;binary", dsServiceName));
    } catch (NamingException e) {
      throw new RuntimeException(e);
    }

    LOGGER.info("Successfully created an Initial LDAP context");

    nETBIOSName = (String) get("(ncName=" + dn + ")",
        "nETBIOSName", configurationNamingContext);
    dnsRoot = (String) get("(ncName=" + dn + ")", "dnsRoot",
        configurationNamingContext);
    LOGGER.log(Level.INFO, "Connected to domain (dn = " + dn + ", netbios = "
        + nETBIOSName + ", hostname = " + hostName + ", dsServiceName = "
        + dsServiceName + ", highestCommittedUSN = " + highestCommittedUSN
        + ", invocationID = " + invocationID + ", dnsRoot = " + dnsRoot + ")");
  }

  /**
   * Retrieves one attribute from the Active Directory. Used for searching of
   * configuration details.
   * @param filter LDAP filter to search for
   * @param attribute name of attribute to retrieve
   * @param base base name to bind to
   * @return first attribute object
   */
  protected Object get(String filter, String attribute, String base) {
    searchCtls.setReturningAttributes(new String[] {attribute});
    try {
      connect();  // re-establish LDAP connection, if necessary
      NamingEnumeration<SearchResult> ldapResults =
          ldapContext.search(base, filter, searchCtls);
      if (!ldapResults.hasMore()) {
        return null;
      }
      SearchResult sr = ldapResults.next();
      Attributes attrs = sr.getAttributes();
      Attribute at = attrs.get(attribute);
      if (at != null) {
        return attrs.get(attribute).get(0);
      }
    } catch (NamingException e) {
      LOGGER.log(Level.WARNING,
          "Failed retrieving " + filter + " from AD server", e);
    }
    return null;
  }

  /**
   * Set request controls on the LDAP query
   * @param deleted include deleted control
   */
  private void setControls(boolean deleted) {
    try {
      Control[] controls;
      if (deleted) {
        controls = new Control[] {
            new PagedResultsControl(1000, false), new DeletedControl()};
      } else {
        controls = new Control[] {
            new PagedResultsControl(1000, false)};
      }
      ldapContext.setRequestControls(controls);
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Couldn't initialize LDAP paging control. "
        + "Will continue without paging - this can cause issue if there"
        + "are more than 1000 members in one group.", e);
    } catch (NamingException e) {
      LOGGER.log(Level.WARNING, "Couldn't initialize LDAP paging control. "
          + "Will continue without paging - this can cause issue if there"
          + "are more than 1000 members in one group.", e);
    }
  }

  /**
   * Searches Active Directory and creates AdEntity on each result found
   * @param filter LDAP filter to search in the AD for
   * @param attributes list of attributes to retrieve
   * @return list of entities found
   */
  public Set<AdEntity> search(String filter, boolean deleted,
      String[] attributes) throws InterruptedNamingException {
    Set<AdEntity> results = new HashSet<AdEntity>();
    searchCtls.setReturningAttributes(attributes);
    setControls(deleted);
    try {
      connect();  // re-establish LDAP connection, if necessary
      byte[] cookie = null;
      do {
        NamingEnumeration<SearchResult> ldapResults =
            ldapContext.search(dn, filter, searchCtls);
        while (ldapResults.hasMoreElements()) {
          SearchResult sr = ldapResults.next();
          try {
            results.add(new AdEntity(sr));
          } catch (Exception ex) {
            // It is possible that Search Result returned is missing
            // few attributes required to construct AD Entity object.
            // Such results will be ignored.
            // This exception is logged and ignored to allow connector to
            // continue crawling otherwise connector can not
            // proceed with traversal.
            LOGGER.log(Level.WARNING, "Error Processing Search Result "
                + sr, ex);
          }
        }
        cookie = null;
        Control[] resultResponseControls = ldapContext.getResponseControls();
        for (int i = 0; i < resultResponseControls.length; ++i) {
          if (resultResponseControls[i] instanceof
              PagedResultsResponseControl) {
            cookie = ((PagedResultsResponseControl) resultResponseControls[i])
                .getCookie();
            ldapContext.setRequestControls(new Control[] {
                new PagedResultsControl(1000, cookie, Control.CRITICAL)});
          }
        }
      } while ((cookie != null) && (cookie.length != 0));

      // if we received non complete attribute we need to use range based
      // retrieval to get the rest of members
      for (AdEntity g : results) {
        if (!g.isGroup() || g.areAllMembershipsRetrieved()) {
          continue;
        }

        int batch = g.getMembers().size();
        int start = g.getMembers().size();
        do {
          String memberRange = String.format("member;Range=%d-%d", start,
              start + batch - 1);
          LOGGER.finest(
              "Retrieving additional groups for [" + g + "] " + memberRange);
          searchCtls.setReturningAttributes(new String[] {memberRange});
          NamingEnumeration<SearchResult> ldapResults = ldapContext.search(
              dn, "(sAMAccountName=" + g.getSAMAccountName() +")", searchCtls);
          SearchResult sr = ldapResults.next();
          int found = g.appendGroups(sr);
          start += found;
        } while (!g.areAllMembershipsRetrieved());
      }
    } catch (InterruptedNamingException e) {
      throw e;
    } catch (NamingException e) {
      LOGGER.log(Level.WARNING, "", e);
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Couldn't initialize LDAP paging control. Will"
          + " continue without paging - this can cause issue if there are more"
          + " than 1000 members in one group. ",
          e);
    }
    return results;
  }

  /**
   * @return the distinguished Name
   */
  public final String getDn() {
    return dn;
  }

  /**
   * @return the dsServiceName
   */
  public String getDsServiceName() {
    return dsServiceName;
  }

  /**
   * @return the invocationID
   */
  public String getInvocationID() {
    return invocationID;
  }

  /**
   * @return the nETBIOSName
   */
  public String getnETBIOSName() {
    return nETBIOSName;
  }

  /**
   * @return the sid
   */
  public String getSid() {
    return sid;
  }

  class DeletedControl implements Control {
    @Override
    public byte[] getEncodedValue() {
        return new byte[] {};
    }
    @Override
    public String getID() {
        return "1.2.840.113556.1.4.417";
    }
    @Override
    public boolean isCritical() {
        return true;
    }
  }

  @Override
  public String toString() {
    return "[" + nETBIOSName + "] ";
  }

  /**
   * @return the highestCommittedUSN
   */
  public long getHighestCommittedUSN() {
    return highestCommittedUSN;
  }

  public String getHostName() {
    return hostName;
  }
}
