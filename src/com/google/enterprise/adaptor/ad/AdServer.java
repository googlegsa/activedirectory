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

import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.StartupException;

import java.io.IOException;
import java.net.ConnectException;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.InterruptedNamingException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
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
  @VisibleForTesting
  int port;
  private String principal;
  private String password;

  // properties used by various specific searches
  private String userSearchBaseDN;
  private String groupSearchBaseDN;
  private String userSearchFilter;
  private String groupSearchFilter;

  // retrieved properties of the Active Directory controller
  private String nETBIOSName;
  private String dn;
  private String configurationNamingContext;
  private String dsServiceName;
  private String sid;
  private long highestCommittedUSN;
  private String invocationID;
  private String dnsRoot;
  private String ldapTimeoutInMillis;

  public AdServer(Method connectMethod, String hostName,
      int port, String principal, String password,
      String userSearchBaseDN, String groupSearchBaseDN,
      String userSearchFilter, String groupSearchFilter,
      String ldapTimeoutInMillis)
      throws StartupException {
    this(hostName, userSearchBaseDN, groupSearchBaseDN, userSearchFilter,
        groupSearchFilter, createLdapContext(connectMethod, hostName, port,
            principal, password, ldapTimeoutInMillis));
    this.connectMethod = connectMethod;
    this.port = port;
    this.principal = principal;
    this.password = password;
    this.ldapTimeoutInMillis = ldapTimeoutInMillis;
  }

  @VisibleForTesting
  AdServer(String hostName, String userSearchBaseDN, String groupSearchBaseDN,
      String userSearchFilter, String groupSearchFilter,
      LdapContext ldapContext) {
    this.hostName = hostName;
    this.userSearchBaseDN = userSearchBaseDN;
    this.groupSearchBaseDN = groupSearchBaseDN;
    this.userSearchFilter = userSearchFilter;
    this.groupSearchFilter = groupSearchFilter;
    this.ldapContext = ldapContext;
    searchCtls = new SearchControls();
    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
  }

  /**
   * Normally called (only) by public constructor
   */
  private static LdapContext createLdapContext(Method connectMethod,
      String hostName, int port, String principal, String password,
      String ldapTimeoutInMillis) throws StartupException {
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
    // TODO(myk): See if we can specify a value in the configuration file to
    // allow us to override this, for unit tests.
    env.put(Context.INITIAL_CONTEXT_FACTORY,
        "com.sun.jndi.ldap.LdapCtxFactory");
    // Connecting to configuration naming context is very slow for crawl users
    // in large multidomain environment, which belong to thousands of groups
    env.put("com.sun.jndi.ldap.read.timeout", ldapTimeoutInMillis);
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, principal);
    env.put(Context.SECURITY_CREDENTIALS, password);

    String ldapUrl = connectMethod.protocol() + hostName + ":" + port;
    LOGGER.config("LDAP provider url: " + ldapUrl);
    env.put(Context.PROVIDER_URL, ldapUrl);
    try {
      return new InitialLdapContext(env, null);
    } catch (NamingException ne) {
      // display (throw) a "nicer" exception message when we cannot connect.
      // This can be an AuthenticationException (wrong user name or password) or
      // a ConnectException (wrong hostname).
      Throwable cause = ne.getCause();
      boolean replaceException = false;
      boolean abortStartup = false;
      if (cause instanceof ConnectException) {
        ConnectException ce = (ConnectException) cause;
        if (ce.getMessage() != null
            && (ce.getMessage().contains("Connection timed out")
                || ce.getMessage().contains("Connection refused"))) {
          replaceException = true;
        }
      } else if (ne instanceof AuthenticationException) {
        // this is the only exception we flag as a StartupException.
        replaceException = true;
        abortStartup = true;
      } else if (ne instanceof CommunicationException) {
        replaceException = true;
      } else if (ne instanceof ServiceUnavailableException) {
        replaceException = true;
      }
      if (replaceException) {
        String warning = String.format("Cannot connect to server \"%s\" as "
            + "user \"%s\" with the specified password.  Please make sure "
            + "they are specified correctly.  If the AD server is currently "
            + "down, please try again later.", hostName, principal);
        if ((port == 3268) || (port == 3269)) {
          warning = "AD Adaptor must be run against the Domain Controller "
            + "(typically, port 389 for HTTP or port 636 for SSL), not the "
            + "Global Catalog.";
          abortStartup = true;
        }
        if (abortStartup) {
          throw new StartupException(warning, ne);
        } else {
          throw new RuntimeException(warning, ne);
        }
      }
      // wasn't the specific error we're looking for -- rethrow it.
      // <code>RuntimeException</code> is caught by the library, and retried.
      throw new RuntimeException(ne);
    }
  }

  @VisibleForTesting
  void recreateLdapContext() throws StartupException {
    ldapContext = createLdapContext(connectMethod, hostName, port, principal,
        password, ldapTimeoutInMillis);
  }

  /**
   * Connects to the Active Directory server and retrieves AD configuration
   * information.
   * <p>This method is used for crawling as well as authorization of credentials
   * against Active Directory.  Calling this method after a connection has been
   * established will refresh the connection attributes (e.g.
   * <code>highestCommittedUSN</code>).
   */
  public void ensureConnectionIsCurrent()
      throws CommunicationException, NamingException {
    Attributes attributes;
    try {
      attributes = ldapContext.getAttributes("");
    } catch (CommunicationException ce) {
      LOGGER.log(Level.FINER,
          "Reconnecting to AdServer after detecting issue", ce);
      try {
        recreateLdapContext();
      } catch (StartupException se) {
        // authentication issues
        NamingException ne = new NamingException("recreateLdapContext problem");
        ne.setRootCause(se);
        throw ne;
      }
      attributes = ldapContext.getAttributes("");
    } catch (NamingException ne) {
      if (ne.getMessage() != null
          && ne.getMessage().contains("read timed out")) {
        LOGGER.log(Level.WARNING, "Read timeout insufficient", ne);
        LOGGER.log(Level.WARNING, "Consider increasing the value of "
            + "``ad.ldapReadTimeoutSeconds'' in the config file.");
      }
      // rethrow the exception, whether or not we were able to give advice.
      throw(ne);
    }
    dn = attributes.get("defaultNamingContext").get(0).toString();
    dsServiceName = attributes.get("dsServiceName").get(0).toString();
    highestCommittedUSN = Long.parseLong(attributes.get(
        "highestCommittedUSN").get(0).toString());
    configurationNamingContext = attributes.get(
        "configurationNamingContext").get(0).toString();
  }

  public void initialize() throws InvalidConfigurationException {
    try {
      ensureConnectionIsCurrent();
      sid = AdEntity.getTextSid((byte[]) get(
          "distinguishedName=" + dn, "objectSid;binary", dn));
      invocationID = AdEntity.getTextGuid((byte[]) get(
          "distinguishedName=" + dsServiceName,
          "invocationID;binary", dsServiceName));
    } catch (NamingException e) {
      throw new RuntimeException(e);
    } catch (NullPointerException npe) {
      String reason = "non-AD LDAP server detected.  AD Adaptor must be run "
          + "against an Active Directory domain controller.";
      if ((port == 3268) || (port == 3269)) {
        reason = "AD Adaptor must be run against the Domain Controller "
            + "(typically, port 389 for HTTP or port 636 for SSL), not the "
            + "Global Catalog.";
      }
      throw new InvalidConfigurationException(reason);
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
      ensureConnectionIsCurrent();
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
   * @param baseDN baseDN for the search (use "dn" when empty/null)
   * @param filter LDAP filter to search in the AD for
   * @param attributes list of attributes to retrieve
   * @return list of entities found
   */
  public Set<AdEntity> search(String baseDN, String filter, boolean deleted,
      String[] attributes) throws InterruptedNamingException {
    Set<AdEntity> results = new HashSet<AdEntity>();
    searchCtls.setReturningAttributes(attributes);
    setControls(deleted);
    if (null == baseDN || "".equals(baseDN)) {
      baseDN = dn;
    }
    try {
      ensureConnectionIsCurrent();
      byte[] cookie = null;
      do {
        NamingEnumeration<SearchResult> ldapResults =
            ldapContext.search(baseDN, filter, searchCtls);
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
        Control[] controls = ldapContext.getResponseControls();
        for (int i = 0; controls != null && i < controls.length; ++i) {
          if (controls[i] instanceof PagedResultsResponseControl) {
            cookie = ((PagedResultsResponseControl) controls[i]).getCookie();
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
              baseDN, "(sAMAccountName=" + g.getSAMAccountName() + ")",
              searchCtls);
          SearchResult sr = ldapResults.next();
          int found = g.appendGroups(sr);
          start += found;
        } while (!g.areAllMembershipsRetrieved());
      }
    } catch (InterruptedNamingException e) {
      throw e;
    } catch (NameNotFoundException e) {
      /* this can either be corrected by fixing the configuration file, or by
         creating the particular baseDN on the AdServer -- hence we don't just
         throw an InvalidConfigurationException here. */
      throw new IllegalStateException("Could not find requested baseDN of "
          + baseDN + " -- check your configuration file and make sure your "
          + "specified ad.userSearchBaseDN and ad.groupSearchBaseDN properties "
          + "are properly set.", e);
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

  public String getUserSearchBaseDN() {
    return userSearchBaseDN;
  }

  public String getGroupSearchBaseDN() {
    return groupSearchBaseDN;
  }

  public String getUserSearchFilter() {
    return userSearchFilter;
  }

  public String getGroupSearchFilter() {
    return groupSearchFilter;
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
