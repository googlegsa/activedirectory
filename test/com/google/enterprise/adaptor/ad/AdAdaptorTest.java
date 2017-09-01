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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.common.collect.Sets;

import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Adaptor;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.TestHelper;
import com.google.enterprise.adaptor.UserPrincipal;
import com.google.enterprise.adaptor.testing.RecordingDocIdPusher;
import com.google.enterprise.adaptor.testing.RecordingResponse;

import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.CommunicationException;
import javax.naming.InterruptedNamingException;
import javax.naming.NamingException;


/** Test cases for {@link AdAdaptor}. */
public class AdAdaptorTest {
  public static final int BRIEF_DELAY_IN_MILLISECONDS = 25;

  @Test
  public void testNoop() {
  }

  @Test
  public void testGroupCatalogConstructor() {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true).build();
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogEquals() {
    AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder().build();
    golden.members.put(new AdEntity("Test", "dn=Test"),
        Sets.newHashSet("Test"));
    final Map<AdEntity, Set<String>> goldenWellKnownMembership =
        golden.wellKnownMembership;

    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    groupCatalog.members.put(new AdEntity("Test", "dn=Test"),
        Sets.newHashSet("Test"));

    assertEquals(golden, groupCatalog);

    assertFalse(golden.equals(42));

    almostClear(groupCatalog);
    groupCatalog.add(golden);
    assertEquals(golden, groupCatalog);

    almostClear(groupCatalog);
    groupCatalog.add(golden);
    groupCatalog.entities.clear();
    assertFalse(golden.equals(groupCatalog));

    almostClear(groupCatalog);
    groupCatalog.add(golden);
    groupCatalog.members.clear();
    assertFalse(golden.equals(groupCatalog));

    almostClear(groupCatalog);
    groupCatalog.add(golden);
    groupCatalog.bySid.clear();
    assertFalse(golden.equals(groupCatalog));

    almostClear(groupCatalog);
    groupCatalog.add(golden);
    groupCatalog.byDn.clear();
    assertFalse(golden.equals(groupCatalog));

    almostClear(groupCatalog);
    groupCatalog.add(golden);
    groupCatalog.domain.clear();
    assertFalse(golden.equals(groupCatalog));
    assertFalse(golden.hashCode() == groupCatalog.hashCode());

    almostClear(groupCatalog);
    groupCatalog.add(golden);
    assertEquals(golden, groupCatalog);
    groupCatalog.wellKnownMembership.get(groupCatalog.everyone).add("fakeDN");
    assertFalse(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogReadFrom() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a group
    String filter = "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))";
    String searchDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("dn_for_user_1", "dn_for_user_2");
    ldapContext.addSearchResult(filter, "cn", searchDn, "group_name")
               .addSearchResult(filter, "objectSid;binary", searchDn,
                   hexStringToByteArray("010100000000000000000000")) // S-1-0-0
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "member", searchDn, members)
               .addSearchResult(filter, "sAMAccountName", searchDn,
                   "name under");

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    final AdEntity goldenEntity = new AdEntity("S-1-0-0",
        "cn=name\\ under,DN_for_default_naming_context");
    goldenEntity.getMembers().addAll(members);
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>();
    goldenMembers.put(goldenEntity, goldenEntity.getMembers());
    final Map<String, AdEntity> goldenSid =
        new HashMap<String, AdEntity>();
    goldenSid.put(goldenEntity.getSid(), goldenEntity);
    final Map<String, AdEntity> goldenDn =
        new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity.getDn(), goldenEntity);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity, "GSA-CONNECTORS");

    AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(goldenEntity))
        .setMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();

    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testMakeFullCatalogFromTwoServersWithDifferentBaseDNsAndFilters()
      throws Exception {
    RecordingDocIdPusher pusher = new RecordingDocIdPusher();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a group to be found by server1
    String filter1 = "(&(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))(gsf1))";
    // the following matches the GroupSearchBaseDn for server 1
    String baseDn1 = "ou=gsbn1";
    List<String> fakeMembers = Arrays.asList("dn_for_user_1", "dn_for_user_2");
    ldapContext.addSearchResult(filter1, "cn", baseDn1, "group1")
               .addSearchResult(filter1, "objectSid;binary", baseDn1,
                   hexStringToByteArray("010100000000000000000000")) // S-1-0-0
               .addSearchResult(filter1, "objectGUID;binary", baseDn1,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter1, "member", baseDn1, fakeMembers)
               .addSearchResult(filter1, "sAMAccountName", baseDn1,
                   "name under");
    // add a group to be found by server2
    String filter2 = "(&(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))(gsf2))";
    // the following matches the GroupSearchBaseDn for server 2
    String baseDn2 = "ou=gsbn2";
    ldapContext.addSearchResult(filter2, "cn", baseDn2, "group2")
               .addSearchResult(filter2, "objectSid;binary", baseDn2,
                   hexStringToByteArray("010100000000000001000000")) // S-1-0-1
               .addSearchResult(filter2, "objectGUID;binary", baseDn2,
                   hexStringToByteArray("000102030405060708090a0b0f"))
               .addSearchResult(filter2, "member", baseDn2, fakeMembers)
               .addSearchResult(filter2, "sAMAccountName", baseDn2,
                   "name under");

    // create a configuration to specify two servers, each with different
    // BaseDNs and Filters
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1,server2");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.userSearchBaseDN", "ou=usbn1");
    configEntries.put("ad.servers.server1.groupSearchBaseDN", "ou=gsbn1");
    configEntries.put("ad.servers.server1.userSearchFilter", "usf1");
    configEntries.put("ad.servers.server1.groupSearchFilter", "gsf1");
    configEntries.put("ad.servers.server2.host", "localhost");
    configEntries.put("ad.servers.server2.userSearchBaseDN", "ou=usbn2");
    configEntries.put("ad.servers.server2.groupSearchBaseDN", "ou=gsbn2");
    configEntries.put("ad.servers.server2.userSearchFilter", "usf2");
    configEntries.put("ad.servers.server2.groupSearchFilter", "gsf2");
    configEntries.put("ad.defaultUser", "defaultUser");
    configEntries.put("ad.defaultPassword", "password");
    configEntries.put("ad.ldapReadTimeoutSecs", "");
    configEntries.put("ad.userSearchBaseDN", "cn=UserBaseDNNotFound");
    configEntries.put("ad.groupSearchBaseDN", "cn=GroupBaseDNNotFound");
    configEntries.put("ad.userSearchFilter", "cn=UserNotFound");
    configEntries.put("ad.groupSearchFilter", "cn=GroupNotFound");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    AdAdaptor adAdaptor = new FakeAdaptorWithSharedMockLdapContext(ldapContext);
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    Map<GroupPrincipal, Collection<Principal>> results =
        pusher.getGroupDefinitions();
    // the above (eventually) calls AdAdaptor.init() with the specified config.

    final AdEntity goldenEntity1 = new AdEntity("S-1-0-0",
        "cn=name\\ under," + baseDn1);
    final AdEntity goldenEntity2 = new AdEntity("S-1-0-1",
        "cn=name\\ under," + baseDn2);
    final AdEntity everyone = new AdEntity("S-1-1-0", "CN=Everyone");
    final AdEntity authUsers = new AdEntity("S-1-5-11",
        "CN=Authenticated Users,DC=NT Authority");
    final AdEntity interactive = new AdEntity("S-1-5-4",
        "CN=Interactive,DC=NT Authority");
    goldenEntity1.getMembers().addAll(fakeMembers);
    goldenEntity2.getMembers().addAll(fakeMembers);
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>();
    goldenMembers.put(goldenEntity1, goldenEntity1.getMembers());
    goldenMembers.put(goldenEntity2, goldenEntity2.getMembers());
    final Map<String, AdEntity> goldenSid =
        new HashMap<String, AdEntity>();
    goldenSid.put(goldenEntity1.getSid(), goldenEntity1);
    goldenSid.put(goldenEntity2.getSid(), goldenEntity2);
    goldenSid.put("S-1-1-0", everyone);
    goldenSid.put("S-1-5-11", authUsers);
    goldenSid.put("S-1-5-4", interactive);
    final Map<String, AdEntity> goldenDn =
        new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity1.getDn(), goldenEntity1);
    goldenDn.put(goldenEntity2.getDn(), goldenEntity2);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity1, "GSA-CONNECTORS");
    goldenDomain.put(goldenEntity2, "GSA-CONNECTORS");

    AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(goldenEntity1, goldenEntity2, everyone,
            authUsers, interactive))
        .setMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();

    AdAdaptor.GroupCatalog actual = adAdaptor.makeFullCatalog();
    assertTrue(golden.equals(actual));
  }

  @Test
  public void testGroupCatalogReadFromReturnsDisabledGroup() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a disabled group
    String filter = "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))";
    String searchDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("dn_for_user_1", "dn_for_user_2");
    ldapContext.addSearchResult(filter, "cn", searchDn, "group_name")
               .addSearchResult(filter, "objectSid;binary", searchDn,
                   hexStringToByteArray("010100000000000000000000")) // S-1-0-0
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "member", searchDn, members)
               .addSearchResult(filter, "userAccountControl", searchDn, "514")
               .addSearchResult(filter, "sAMAccountName", searchDn,
                   "name under");

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    AdEntity[] groupEntity = groupCatalog.entities.toArray(new AdEntity[0]);
    final AdEntity goldenEntity = groupEntity[0];
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>();
    goldenMembers.put(goldenEntity, goldenEntity.getMembers());
    final Map<String, AdEntity> goldenSid =
        new HashMap<String, AdEntity>();
    goldenSid.put(goldenEntity.getSid(), goldenEntity);
    AdEntity everyone = groupCatalog.bySid.get("S-1-1-0");
    AdEntity authUsers = groupCatalog.bySid.get("S-1-5-11");
    AdEntity interactive = groupCatalog.bySid.get("S-1-5-4");
    goldenSid.put("S-1-1-0", everyone);
    goldenSid.put("S-1-5-11", authUsers);
    goldenSid.put("S-1-5-4", interactive);
    final Map<String, AdEntity> goldenDn =
        new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity.getDn(), goldenEntity);
    goldenDn.put(everyone.getDn(), everyone);
    goldenDn.put(authUsers.getDn(), authUsers);
    goldenDn.put(interactive.getDn(), interactive);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity, "GSA-CONNECTORS");
    goldenDomain.put(interactive, "NT Authority");
    goldenDomain.put(authUsers, "NT Authority");

    AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(goldenEntity))
        .setMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();

    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogReadFromReturnsUser() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a user
    String filter = "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))";
    String searchDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", searchDn, "group_name")
               .addSearchResult(filter, "objectSid;binary", searchDn,
                                      // S-1-5-32-544: local Admin. group
                   hexStringToByteArray("01020000000000052000000020020000"))
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "primaryGroupId", searchDn, "users")
               .addSearchResult(filter, "sAMAccountName", searchDn, "sam");

    AdEntity userGroup = new AdEntity("S-1-5-32-users", "users");
    AdEntity everyone = new AdEntity("S-1-1-0", "CN=Everyone");
    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.bySid.put("S-1-5-32-users", userGroup);
    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    final AdEntity goldenEntity = new AdEntity("S-1-5-32-544",
        "cn=name\\ under,DN_for_default_naming_context", "users", "sam");
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>(); // stores (only) primary members
    goldenMembers.put(userGroup, Sets.newHashSet(goldenEntity.getDn()));
    final Map<String, AdEntity> goldenSid = new HashMap<String, AdEntity>();
    goldenSid.put("S-1-5-32-users", userGroup);
    goldenSid.put("S-1-5-32-544", goldenEntity);
    final Map<String, AdEntity> goldenDn = new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity.getDn(), goldenEntity);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity, "BUILTIN");

    AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(goldenEntity, userGroup, everyone))
        .setPrimaryMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();
    golden.wellKnownMembership.get(golden.everyone).add(goldenEntity.getDn());
    assertTrue(golden.equals(groupCatalog));

    // make sure readEverythingFrom call is idempotent
    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogReadFromReturnsUserMissingPrimaryGroup()
      throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a user
    String filter = "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))";
    String searchDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", searchDn, "group_name")
               .addSearchResult(filter, "objectSid;binary", searchDn,
                                      // S-1-5-32-544: local Admin. group
                   hexStringToByteArray("01020000000000052000000020020000"))
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "primaryGroupId", searchDn, "users")
               .addSearchResult(filter, "sAMAccountName", searchDn, "sam");

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    final AdEntity goldenEntity = new AdEntity("S-1-5-32-544",
        "cn=name\\ under,DN_for_default_naming_context", "users", "sam");
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>();
    final Map<String, AdEntity> goldenSid = new HashMap<String, AdEntity>();
    goldenSid.put("S-1-5-32-544", goldenEntity);
    final Map<String, AdEntity> goldenDn = new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity.getDn(), goldenEntity);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity, "BUILTIN");

    final AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(goldenEntity))
        .setMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();
    assertTrue(golden.equals(groupCatalog));

    // make sure readEverythingFrom call is idempotent
    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testLdapQueriesWithNoFiltersOrBaseDns() throws Exception {
    final FakeAdaptor adAdaptor = new FakeAdaptor();
    final FakeCatalog groupCatalog = new FakeCatalog(
        defaultLocalizedStringMap(), "example.com", false);
    MockLdapContext ldapContext = defaultMockLdapContext();
    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();
    final String expectedGroupQuery = "(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))";
    assertEquals(expectedGroupQuery,
        groupCatalog.generateGroupLdapQuery(adServer));
    final String expectedUserQuery = "(&(objectClass=user)"
        + "(objectCategory=person))";
    assertEquals(expectedUserQuery,
           groupCatalog.generateUserLdapQuery(adServer));
    final String expectedQuery = "(|" + expectedGroupQuery + expectedUserQuery
        + ")";
    assertEquals(expectedQuery, groupCatalog.generateLdapQuery(adServer));

    groupCatalog.resetCrawlFlags();
    assertFalse(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);
    assertTrue(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.resetCrawlFlags();
    groupCatalog.readUpdatesFrom(adServer, "ds_service_name", "0x0123456789abc",
        12345677L); // earlier USN than previous run: does an incremental run
    assertFalse(groupCatalog.ranFullCrawl());
    assertTrue(groupCatalog.ranIncrementalCrawl());
  }

  @Test
  public void testLdapQueriesWithFilters() throws Exception {
    final FakeAdaptor adAdaptor = new FakeAdaptor();
    final FakeCatalog groupCatalog = new FakeCatalog(
        defaultLocalizedStringMap(), "example.com", false);
    MockLdapContext ldapContext = defaultMockLdapContext();
    final AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "ou=UserFilter", "ou=GroupFilter",
        ldapContext);
    adServer.initialize();
    final String expectedGroupQuery = "(&(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))(ou=GroupFilter))";
    assertEquals(expectedGroupQuery,
        groupCatalog.generateGroupLdapQuery(adServer));
    final String expectedUserQuery = "(&(&(objectClass=user)"
        + "(objectCategory=person))(ou=UserFilter))";
    assertEquals(expectedUserQuery,
        groupCatalog.generateUserLdapQuery(adServer));
    final String expectedQuery = "(|" + expectedGroupQuery + expectedUserQuery
        + ")";
    assertEquals(expectedQuery, groupCatalog.generateLdapQuery(adServer));

    groupCatalog.resetCrawlFlags();
    assertFalse(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);
    assertTrue(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.resetCrawlFlags();
    groupCatalog.readUpdatesFrom(adServer, "ds_service_name", "0x0123456789abc",
        12345677L); // earlier USN than previous run: does an incremental run
    assertFalse(groupCatalog.ranFullCrawl());
    assertTrue(groupCatalog.ranIncrementalCrawl());
  }

  @Test
  public void testLdapQueriesWithBaseDNsButNoFilters() throws Exception {
    final FakeAdaptor adAdaptor = new FakeAdaptor();
    final FakeCatalog groupCatalog = new FakeCatalog(
        defaultLocalizedStringMap(), "example.com", false);
    MockLdapContext ldapContext = defaultMockLdapContext();
    final AdServer adServer = new AdServer("localhost", "ou=UserBaseDN",
        "ou=GroupBaseDN", "" /*userSearchFilter*/, "" /*groupSearchFilter*/,
        ldapContext);
    adServer.initialize();
    final String expectedGroupQuery = "(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))";
    assertEquals(expectedGroupQuery,
        groupCatalog.generateGroupLdapQuery(adServer));
    final String expectedUserQuery = "(&(objectClass=user)"
        + "(objectCategory=person))";
    assertEquals(expectedUserQuery,
        groupCatalog.generateUserLdapQuery(adServer));
    final String expectedQuery = "(|" + expectedGroupQuery + expectedUserQuery
        + ")";
    try {
      String query = groupCatalog.generateLdapQuery(adServer);
      fail("Did not catch expected exception!");
    } catch (IllegalArgumentException iae) {
      assertTrue(iae.toString().contains("not handling differing BaseDNs"));
    }

    groupCatalog.resetCrawlFlags();
    assertFalse(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);
    assertTrue(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.resetCrawlFlags();
    groupCatalog.readUpdatesFrom(adServer, "ds_service_name", "0x0123456789abc",
        12345677L); // earlier USN than previous run: does an incremental run
    assertFalse(groupCatalog.ranFullCrawl());
    assertTrue(groupCatalog.ranIncrementalCrawl());
  }

  @Test
  public void testLdapQueriesWithBaseDNsAndFilters() throws Exception {
    final FakeAdaptor adAdaptor = new FakeAdaptor();
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    final AdServer adServer = new AdServer("localhost", "ou=UserBaseDn",
        "ou=GroupBaseDn", "ou=UserFilter", "ou=GroupFilter", ldapContext);
    adServer.initialize();
    final String expectedGroupQuery = "(&(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))(ou=GroupFilter))";
    assertEquals(expectedGroupQuery,
        groupCatalog.generateGroupLdapQuery(adServer));
    final String expectedUserQuery = "(&(&(objectClass=user)"
        + "(objectCategory=person))(ou=UserFilter))";
    assertEquals(expectedUserQuery,
        groupCatalog.generateUserLdapQuery(adServer));
    final String expectedQuery = "(|" + expectedGroupQuery + expectedUserQuery
        + ")";
    try {
      String query = groupCatalog.generateLdapQuery(adServer);
      fail("Did not catch expected exception!");
    } catch (IllegalArgumentException iae) {
      assertTrue(iae.toString().contains("not handling differing BaseDNs"));
    }

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ false);
    groupCatalog.readUpdatesFrom(adServer, "ds_service_name", "0x0123456789abc",
        12345677L); // earlier USN than previous run: does an incremental run
  }

  @Test
  public void testLdapQueriesWithSameBaseDNsButNoFilters() throws Exception {
    final FakeAdaptor adAdaptor = new FakeAdaptor();
    final FakeCatalog groupCatalog = new FakeCatalog(
        defaultLocalizedStringMap(), "example.com", false);
    MockLdapContext ldapContext = defaultMockLdapContext();
    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();
    String query = groupCatalog.generateLdapQuery(adServer);
    assertEquals(query, "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))");
  }

  @Test
  public void testFullCrawlVersusIncrementalCrawlFlow() throws Exception {
    final FakeAdaptor adAdaptor = new FakeAdaptor();
    final FakeCatalog groupCatalog = new FakeCatalog(
        defaultLocalizedStringMap(), "example.com", false);
    MockLdapContext ldapContext = defaultMockLdapContext();
    AdServer adServer = new AdServer("localhost", "userSearchBaseDN",
        "groupSearchBaseDN", "userSearchFilter", "groupSearchFilter",
        ldapContext);
    adServer.initialize();

    groupCatalog.resetCrawlFlags();
    assertFalse(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);
    assertTrue(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.resetCrawlFlags();
    groupCatalog.readUpdatesFrom(adServer, "other_ds_service_name",
        "0x0123456789abc", 12345678L);
    assertTrue(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.resetCrawlFlags();
    groupCatalog.readUpdatesFrom(adServer, "ds_service_name",
        "otherInvocationId", 12345678L);
    assertTrue(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.resetCrawlFlags();
    groupCatalog.readUpdatesFrom(adServer, "ds_service_name", "0x0123456789abc",
        12345678L); // last USN as previous run: no crawl
    assertFalse(groupCatalog.ranFullCrawl());
    assertFalse(groupCatalog.ranIncrementalCrawl());

    groupCatalog.resetCrawlFlags();
    groupCatalog.readUpdatesFrom(adServer, "ds_service_name", "0x0123456789abc",
        12345677L); // earlier USN than previous run: does an incremental run
    assertFalse(groupCatalog.ranFullCrawl());
    assertTrue(groupCatalog.ranIncrementalCrawl());

    // attempt to invoke incremental crawl during a full crawl
    MoreFakeAdaptor adaptor = new MoreFakeAdaptor();
    adaptor.resetCrawlFlags();
    Thread fullThread = new FullCrawlThread(adaptor);
    Thread incrementalThread = new IncrementalCrawlThread(adaptor);
    fullThread.start();
    try {
      Thread.sleep(BRIEF_DELAY_IN_MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new InterruptedNamingException(ex.getMessage());
    }
    incrementalThread.start();
    fullThread.join();
    incrementalThread.join();
    assertTrue(adaptor.ranFullCrawl());
    assertFalse(adaptor.ranIncrementalCrawl());

    // invoke full crawl during an incremental crawl
    incrementalThread = new IncrementalCrawlThread(adaptor);
    fullThread = new FullCrawlThread(adaptor);
    adaptor.resetCrawlFlags();
    incrementalThread.start();
    try {
      Thread.sleep(BRIEF_DELAY_IN_MILLISECONDS);
    } catch (InterruptedException ex) {
      throw new InterruptedNamingException(ex.getMessage());
    }
    fullThread.start();
    incrementalThread.join();
    fullThread.join();
    assertTrue(adaptor.ranFullCrawl());
    assertTrue(adaptor.ranIncrementalCrawl());
  }

  @Test
  public void testGroupCatalogReadFromIncrementalCrawl() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a group
    String filter = "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))";
    String incrementalFilter = "(&(uSNChanged>=12345678)" + filter + ")";
    String searchDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("dn_for_user_1", "dn_for_user_2");
    ldapContext.addSearchResult(filter, "cn", searchDn, "group_name")
               .addSearchResult(filter, "objectSid;binary", searchDn,
                   hexStringToByteArray("010100000000000000000000")) // S-1-0-0
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "member", searchDn, members)
               .addSearchResult(filter, "sAMAccountName", searchDn,
                   "name under");
    ldapContext.addSearchResult(incrementalFilter, "cn", searchDn, "group_name")
               .addSearchResult(incrementalFilter, "objectSid;binary", searchDn,
                   hexStringToByteArray("010100000000000000000000")) // S-1-0-0
               .addSearchResult(incrementalFilter, "objectGUID;binary",
                   searchDn, hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(incrementalFilter, "member", searchDn, members)
               .addSearchResult(incrementalFilter, "sAMAccountName", searchDn,
                   "name under");
    // and a new user (under the incremental filter)
    ldapContext.addSearchResult(incrementalFilter, "cn", searchDn, "admin_user")
           .addSearchResult(incrementalFilter, "objectSid;binary", searchDn,
                      // S-1-5-32-544: local Admin. group
           hexStringToByteArray("01020000000000052000000020020000"))
           .addSearchResult(incrementalFilter, "objectGUID;binary", searchDn,
           hexStringToByteArray("000102030405060708090a0b0e"))
           .addSearchResult(incrementalFilter, "primaryGroupId", searchDn,
               "users")
           .addSearchResult(incrementalFilter, "sAMAccountName", searchDn,
               "sam2");

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    // first, do a full crawl
    Set<AdEntity> updateResults = groupCatalog.readUpdatesFrom(adServer, null,
        "0x0123456789abc", 12345677L);
    Set<AdEntity> goldenResults = Collections.emptySet();
    assertEquals(goldenResults, updateResults);

    // now do an incremental crawl
    updateResults = groupCatalog.readUpdatesFrom(adServer, "ds_service_name",
        "0x0123456789abc", 12345677L);

    // extract incrementally-added user as one golden entity
    Set<AdEntity> incrementalUserSet = adServer.search("", incrementalFilter,
        false, new String[] { "member", "objectSid;binary", "objectGUID;binary",
            "primaryGroupId", "sAMAccountName" });
    goldenResults = incrementalUserSet;
    assertEquals(goldenResults, updateResults);

    assertEquals(1, incrementalUserSet.size());
    for (AdEntity ae : incrementalUserSet) {
      assertFalse(ae.isGroup());
    }
    AdEntity[] searchedEntity = incrementalUserSet.toArray(new AdEntity[0]);
    final AdEntity goldenUserEntity = searchedEntity[0];

    // extract group from full crawl as the other golden entity
    Set<AdEntity> fullyCrawledGroupSet = adServer.search("", filter, false,
        new String[] { "member", "objectSid;binary", "objectGUID;binary",
            "primaryGroupId", "sAMAccountName" });
    assertEquals(1, fullyCrawledGroupSet.size());
    for (AdEntity ae : fullyCrawledGroupSet) {
      assertTrue(ae.isGroup());
    }
    AdEntity[] groupEntity = fullyCrawledGroupSet.toArray(new AdEntity[0]);
    final AdEntity goldenGroupEntity = new AdEntity("S-1-0-0",
        "cn=name\\ under,DN_for_default_naming_context");

    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>();
    goldenMembers.put(goldenGroupEntity, goldenGroupEntity.getMembers());
    final Map<String, AdEntity> goldenSid =
        new HashMap<String, AdEntity>();
    goldenSid.put(goldenGroupEntity.getSid(), goldenGroupEntity);
    goldenSid.put(goldenUserEntity.getSid(), goldenUserEntity);
    final Map<String, AdEntity> goldenDn =
        new HashMap<String, AdEntity>();
    goldenDn.put(goldenUserEntity.getDn(), goldenUserEntity);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenUserEntity, "BUILTIN");
    goldenDomain.put(goldenGroupEntity, "GSA-CONNECTORS");

    final AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(goldenUserEntity, goldenGroupEntity))
        .setMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();
    assertEquals(golden, groupCatalog);

    // do another incremental crawl with same results
    updateResults = groupCatalog.readUpdatesFrom(adServer, "ds_service_name",
        "0x0123456789abc", 12345677L);
    assertEquals(goldenResults, updateResults);
    assertEquals(golden, groupCatalog);
  }

  @Test
  public void testIncrementalCrawlUpdatesUserPrimaryGroup() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a user and some groups
    String filter = "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))";
    String incrementalFilter = "(&(uSNChanged>=12345678)" + filter + ")";
    String searchDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", searchDn, "username")
               .addSearchResult(filter, "objectSid;binary", searchDn,
                                      // S-1-5-32-544: local Admin. group
                   hexStringToByteArray("01020000000000052000000020020000"))
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "primaryGroupId", searchDn, "groupA")
               .addSearchResult(filter, "sAMAccountName", searchDn, "username");

    // in the increment, we change the user to be a primary member of group B
    ldapContext.addSearchResult(incrementalFilter, "cn", searchDn, "username")
               .addSearchResult(incrementalFilter, "objectSid;binary", searchDn,
                                      // S-1-5-32-544: local Admin. group
                   hexStringToByteArray("01020000000000052000000020020000"))
               .addSearchResult(incrementalFilter, "objectGUID;binary",
                   searchDn, hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(incrementalFilter, "primaryGroupId", searchDn,
                   "groupB")
               .addSearchResult(incrementalFilter, "sAMAccountName", searchDn,
                   "username");

    AdEntity groupA = new AdEntity("S-1-5-32-groupA", "groupA");
    AdEntity groupB = new AdEntity("S-1-5-32-groupB", "groupB");
    AdEntity everyone = new AdEntity("S-1-1-0", "CN=Everyone");
    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.bySid.put("S-1-5-32-groupA", groupA);
    groupCatalog.bySid.put("S-1-5-32-groupB", groupB);
    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    final AdEntity goldenEntity = new AdEntity("S-1-5-32-544",
        "cn=name\\ under,DN_for_default_naming_context", "groupA", "username");
    final AdEntity updatedGoldenEntity = new AdEntity("S-1-5-32-544",
        "cn=name\\ under,DN_for_default_naming_context", "groupB", "username");
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>(); // stores (only) primary members
    goldenMembers.put(groupA, Sets.newHashSet(goldenEntity.getDn()));
    final Map<String, AdEntity> goldenSid = new HashMap<String, AdEntity>();
    goldenSid.put("S-1-5-32-groupA", groupA);
    goldenSid.put("S-1-5-32-groupB", groupB);
    goldenSid.put("S-1-5-32-544", goldenEntity);
    final Map<String, AdEntity> goldenDn = new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity.getDn(), goldenEntity);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity, "BUILTIN");

    AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(goldenEntity, groupA, everyone))
        .setPrimaryMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();
    golden.wellKnownMembership.get(golden.everyone).add(goldenEntity.getDn());
    assertTrue(golden.equals(groupCatalog));

    // make sure readEverythingFrom call is idempotent
    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);
    assertTrue(golden.equals(groupCatalog));

    // first, do a full crawl
    Set<AdEntity> updateResults = groupCatalog.readUpdatesFrom(adServer, null,
        "0x0123456789abc", 12345677L);
    Set<AdEntity> goldenResults = Collections.emptySet();
    assertEquals(goldenResults, updateResults);

    // now do an incremental crawl
    updateResults = groupCatalog.readUpdatesFrom(adServer, "ds_service_name",
        "0x0123456789abc", 12345677L);

    Set<AdEntity> incrementalResults = adServer.search("", incrementalFilter,
        false, new String[] { "member", "objectSid;binary", "objectGUID;binary",
            "primaryGroupId", "sAMAccountName" });
    goldenResults = incrementalResults;
    goldenResults.add(groupB);
    goldenResults.add(everyone);
    assertEquals(goldenResults, updateResults);

    assertEquals(3, incrementalResults.size());
    AdEntity goldenUserEntity = null;
    AdEntity goldenGroupEntity = null;
    int expectedGroupCount = 2;
    for (AdEntity ae : incrementalResults) {
      if (ae.isGroup()) {
        expectedGroupCount--;
        goldenGroupEntity = ae;
      } else {
        goldenUserEntity = ae;
      }
    }
    assertEquals(0, expectedGroupCount);
    assertNotNull(goldenUserEntity);

    final Map<AdEntity, Set<String>> goldenMembers2 =
        new HashMap<AdEntity, Set<String>>();
    goldenMembers2.put(groupA, groupA.getMembers());
    goldenMembers2.put(groupB, Sets.newHashSet(goldenUserEntity.getDn()));
    final Map<String, AdEntity> goldenSid2 =
        new HashMap<String, AdEntity>();
    goldenSid2.put(groupA.getSid(), groupA);
    goldenSid2.put(groupB.getSid(), groupB);
    goldenSid2.put(goldenUserEntity.getSid(), goldenUserEntity);
    final Map<String, AdEntity> goldenDn2 =
        new HashMap<String, AdEntity>();
    goldenDn2.put(goldenUserEntity.getDn(), goldenUserEntity);
    final Map<AdEntity, String> goldenDomain2 = new HashMap<AdEntity, String>();
    goldenDomain2.put(goldenEntity, "BUILTIN");
    goldenDomain2.put(updatedGoldenEntity, "BUILTIN");
    final AdAdaptor.GroupCatalog golden2 = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(Sets.newHashSet(updatedGoldenEntity, groupA, everyone))
        .setPrimaryMembers(goldenMembers2)
        .setBySid(goldenSid2)
        .setByDn(goldenDn2)
        .setDomain(goldenDomain2).build();
    golden2.wellKnownMembership.get(groupCatalog.everyone).add(
        goldenUserEntity.getDn());
    assertEquals(golden2, groupCatalog);

    // do another incremental crawl with same results
    updateResults = groupCatalog.readUpdatesFrom(adServer, "ds_service_name",
        "0x0123456789abc", 12345677L);
    assertEquals(goldenResults, updateResults);
  }

  @Test
  public void testGroupCatalogResolveForeignSecurityPrincipals()
      throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a group
    String filter = "(|(&(objectClass=group)"
    + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
    + "(&(objectClass=user)(objectCategory=person)))";
    String searchDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("sid=null_FSP",
    "sid=S-1-5-21-411,cn=foreignsecurityprincipals,dc=resolved,dc=member",
    "sid=S-1-5-21-911,cn=foreignsecurityprincipals,dc=null,dc=resolution");
    ldapContext.addSearchResult(filter, "cn", searchDn, "group_name")
           .addSearchResult(filter, "objectSid;binary", searchDn,
           hexStringToByteArray("010100000000000000000000")) // S-1-0-0
           .addSearchResult(filter, "objectGUID;binary", searchDn,
           hexStringToByteArray("000102030405060708090a0b0e"))
           .addSearchResult(filter, "member", searchDn, members)
           .addSearchResult(filter, "sAMAccountName", searchDn, "sam");
    // and a user (under another filter)
    String filter2 = "(&(objectClass=user)(objectCategory=person))";
    ldapContext.addSearchResult(filter2, "cn", searchDn, "group_name")
           .addSearchResult(filter2, "objectSid;binary", searchDn,
                      // S-1-5-32-544: local Admin. group
           hexStringToByteArray("01020000000000052000000020020000"))
           .addSearchResult(filter2, "objectGUID;binary", searchDn,
           hexStringToByteArray("000102030405060708090a0b0e"))
           .addSearchResult(filter2, "primaryGroupId", searchDn, "users")
           .addSearchResult(filter2, "sAMAccountName", searchDn, "sam2");

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    // add two additional entities to test all branches of our method.
    // first -- a user
    Set<AdEntity> userEntitySet = adServer.search("", filter2, false,
        new String[] { "cn", "objectSid;binary", "objectGUID;binary",
            "primaryGroupId", "sAMAccountName" });
    assertEquals(1, userEntitySet.size());
    for (AdEntity ae : userEntitySet) {
      assertFalse(ae.isGroup());
      groupCatalog.entities.add(ae);
      groupCatalog.bySid.put("S-1-5-21-411", ae);
    }
    // lastly -- a well known Entity
    AdEntity wellKnownEntity = new AdEntity("WellKnown", "dn=something");
    assertEquals("something", wellKnownEntity.getCommonName());
    assertTrue(wellKnownEntity.isWellKnown());
    groupCatalog.entities.add(wellKnownEntity);

    groupCatalog.resolveForeignSecurityPrincipals(groupCatalog.entities);

    // extract original group entity
    Set<AdEntity> groupEntitySet = adServer.search("", filter, false,
        new String[] { "member", "objectSid;binary", "objectGUID;binary",
            "sAMAccountName" });
    assertEquals(1, groupEntitySet.size());
    for (AdEntity ae : groupEntitySet) {
      assertTrue(ae.isGroup());
    }

    AdEntity[] groupEntity = groupEntitySet.toArray(new AdEntity[0]);
    AdEntity[] userEntity = userEntitySet.toArray(new AdEntity[0]);

    final AdEntity goldenEntity = groupEntity[0];
    for (String groupName : members) {
      goldenEntity.getMembers().add(groupName);
    }
    final Set<AdEntity> goldenEntities = Sets.newHashSet(
        goldenEntity, wellKnownEntity, userEntity[0]);
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>();
    goldenMembers.put(goldenEntity,
        Sets.newHashSet(members.get(0), goldenEntity.getDn()));
    final Map<String, AdEntity> goldenSid =
        new HashMap<String, AdEntity>();
    goldenSid.put("S-1-5-21-411", userEntity[0]);
    goldenSid.put("S-1-0-0", goldenEntity);
    goldenSid.put("S-1-1-0", groupCatalog.bySid.get("S-1-1-0")); // everyone
    goldenSid.put("S-1-5-11", groupCatalog.bySid.get("S-1-5-11")); // auth users
    goldenSid.put("S-1-5-4", groupCatalog.bySid.get("S-1-5-4")); // interactive

    final Map<String, AdEntity> goldenDn = new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity.getDn(), goldenEntity);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity, "GSA-CONNECTORS");
    final AdAdaptor.GroupCatalog golden = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true)
        .setEntities(goldenEntities)
        .setMembers(goldenMembers)
        .setBySid(goldenSid)
        .setByDn(goldenDn)
        .setDomain(goldenDomain).build();
    assertEquals(golden, groupCatalog);

    // make sure resolveForeignSecurityPrincipals call is idempotent
    groupCatalog.resolveForeignSecurityPrincipals(groupCatalog.entities);
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogMakeDefs() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();

    MockLdapContext ldapContext = mockLdapContextForMakeDefs(false);

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    tweakGroupCatalogForMakeDefs(groupCatalog, adServer, false);

    final Map<GroupPrincipal, List<Principal>> golden =
        new HashMap<GroupPrincipal, List<Principal>>();
    {
      golden.put(new GroupPrincipal("sam@GSA-CONNECTORS", "example.com"),
          Arrays.asList(
              new UserPrincipal("sam2", "example.com"),
              new GroupPrincipal("known_group", "example.com")));
      golden.put(new GroupPrincipal("known_group", "example.com"),
          Collections.<Principal>emptyList());
    }
    assertEquals(golden, groupCatalog.makeDefs(groupCatalog.entities));
  }

  @Test
  public void testGroupCatalogMakeDefsWithDisabledGroup() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder().build();

    MockLdapContext ldapContext = mockLdapContextForMakeDefs(true);

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    tweakGroupCatalogForMakeDefs(groupCatalog, adServer, true);

    final Map<GroupPrincipal, List<Principal>> golden =
        new HashMap<GroupPrincipal, List<Principal>>();
    {
      golden.put(new GroupPrincipal("sam@GSA-CONNECTORS", "example.com"),
          Collections.<Principal>emptyList());
      golden.put(new GroupPrincipal("known_group", "example.com"),
          Collections.<Principal>emptyList());
    }
    assertEquals(golden, groupCatalog.makeDefs(groupCatalog.entities));
  }

  @Test
  public void testGroupCatalogMakeDefsWellKnownParent() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new GroupCatalogBuilder()
        .setFeedBuiltinGroups(true).build();
    Logger log = Logger.getLogger(AdAdaptor.class.getName());
    Level oldLevel = log.getLevel();
    log.setLevel(Level.FINER);

    MockLdapContext ldapContext = mockLdapContextForMakeDefs(false);
    String searchDn = "DN_for_default_naming_context";
    String filter = "(objectCategory=person)";
    ldapContext.addSearchResult(filter, "objectSid;binary", searchDn,
                                      // S-1-5-32-544: local Admin. group
                   hexStringToByteArray("01020000000000052000000020020000"))
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "primaryGroupId", searchDn, "users")
               .addSearchResult(filter, "sAMAccountName", searchDn, "");

    AdServer adServer = new AdServer("localhost", "" /*userSearchBaseDN*/,
        "" /*groupSearchBaseDN*/, "" /*userSearchFilter*/,
        "" /*groupSearchFilter*/, ldapContext);
    adServer.initialize();

    groupCatalog.readEverythingFrom(adServer, /*includeMembers=*/ true);

    tweakGroupCatalogForMakeDefs(groupCatalog, adServer, false);
    // now replace the parent group with a well-known one
    AdEntity replacementGroup = new AdEntity("S-1-0-0", "dn=new_parent");
    AdEntity groupWithNoName = new AdEntity("", "dn=");
    AdEntity formerGroup = null;
    for (AdEntity entity : groupCatalog.entities) {
      if ("cn=name\\ under,DN_for_default_naming_context".equals(entity.getDn())
          && (entity.getMembers().size() == 4)) {
        formerGroup = entity;
        for (String member : entity.getMembers()) {
          replacementGroup.getMembers().add(member);
        }
        // trigger the IllegalArgumentException paths by adding empty-named
        // members to the results
        groupCatalog.byDn.put("dn=", groupWithNoName);
        replacementGroup.getMembers().add("dn=");
        groupCatalog.members.put(groupWithNoName, new TreeSet<String>());

        Set<AdEntity> emptyUser = adServer.search("", filter, false,
        new String[] { "objectSid;binary", "objectGUID;binary",
                       "primaryGroupId", "sAMAccountName" });
        assertEquals(1, emptyUser.size());
        for (AdEntity ae : emptyUser) {
          assertFalse(ae.isGroup());
          groupCatalog.byDn.put("dn=emptyUser", ae);
          replacementGroup.getMembers().add("dn=emptyUser");
        }
      }
    }
    assertNotNull(formerGroup);
    groupCatalog.members.put(replacementGroup, replacementGroup.getMembers());
    groupCatalog.members.remove(formerGroup);
    groupCatalog.entities.add(replacementGroup);
    groupCatalog.entities.add(groupWithNoName);
    groupCatalog.entities.remove(formerGroup);

    // rest of this method resembles the previous test, except for the empty-
    // named user and group.
    final Map<GroupPrincipal, List<Principal>> golden =
        new HashMap<GroupPrincipal, List<Principal>>();
    {
      golden.put(new GroupPrincipal("new_parent", "example.com"),
          Arrays.asList(
              new UserPrincipal("sam2", "example.com"),
              new GroupPrincipal("known_group", "example.com")));
      golden.put(new GroupPrincipal("known_group", "example.com"),
          Collections.<Principal>emptyList());
    }
    final Map<GroupPrincipal, List<Principal>> results =
        groupCatalog.makeDefs(groupCatalog.entities);
    assertEquals("unexpected results size", golden.size(), results.size());
    for (Map.Entry<GroupPrincipal, List<Principal>> e : golden.entrySet()) {
      GroupPrincipal key = e.getKey();
      List<Principal> value = e.getValue();
      if (value == null) {
        assertTrue("results did not have key " + key, results.containsKey(key));
        assertNull("non-null result for key " + key, results.get(key));
      } else {
        // Compare the lists for unordered equality, ignoring duplicates.
        assertNotNull("null result for key " + key, results.get(key));
        assertEquals(Sets.newHashSet(value), Sets.newHashSet(results.get(key)));
      }
    }
  }

  // Tests for the methods of the outer class

  @Test
  public void testFakeAdaptorGetDocContent() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    RecordingResponse mockResponse = new RecordingResponse();
    adAdaptor.getDocContent(null, mockResponse);
    assertEquals(RecordingResponse.State.NOT_FOUND, mockResponse.getState());
  }

  @Test
  public void testFakeAdaptorInit() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    RecordingDocIdPusher pusher = new RecordingDocIdPusher();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1,server2");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.servers.server1.user", "user-override");
    configEntries.put("ad.servers.server1.method", "ssl");
    configEntries.put("ad.servers.server2.host", "localhost");
    configEntries.put("ad.servers.server2.port", "1234");
    configEntries.put("ad.servers.server2.password", "password-override");
    configEntries.put("ad.servers.server2.method", "standard");
    configEntries.put("ad.defaultUser", "defaultUser");
    configEntries.put("ad.defaultPassword", "password");
    configEntries.put("ad.ldapReadTimeoutSecs", "");
    configEntries.put("ad.userSearchFilter", "cn=UserNotFound");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    Map<GroupPrincipal, Collection<Principal>> results =
        pusher.getGroupDefinitions();
    // the above (eventually) calls AdAdaptor.init() with the specified config.
  }

  @Test
  public void testFakeAdaptorInitZeroTimeout() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    RecordingDocIdPusher pusher = new RecordingDocIdPusher();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1,server2");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.servers.server1.user", "user-override");
    configEntries.put("ad.servers.server1.method", "ssl");
    configEntries.put("ad.servers.server2.host", "localhost");
    configEntries.put("ad.servers.server2.port", "1234");
    configEntries.put("ad.servers.server2.password", "password-override");
    configEntries.put("ad.servers.server2.method", "standard");
    configEntries.put("ad.defaultUser", "defaultUser");
    configEntries.put("ad.defaultPassword", "password");
    configEntries.put("ad.ldapReadTimeoutSecs", "0");
    configEntries.put("ad.groupSearchFilter", "cn=GroupNotFound");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    Map<GroupPrincipal, Collection<Principal>> results =
        pusher.getGroupDefinitions();
    // the above (eventually) calls AdAdaptor.init() with the specified config.
  }

  @Test
  public void testFakeAdaptorUserAndPasswordSpecified() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    RecordingDocIdPusher pusher = new RecordingDocIdPusher();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.servers.server1.user", "username");
    configEntries.put("ad.servers.server1.password", "password");
    configEntries.put("ad.servers.server1.method", "ssl");
    configEntries.put("ad.userSearchBaseDN", "ou=DoesNotMatter");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    Map<GroupPrincipal, Collection<Principal>> results =
        pusher.getGroupDefinitions();
    // the above (eventually) calls AdAdaptor.init() with the specified config.
  }

  @Test
  public void testFakeAdaptorDefaultUserAndPasswordSpecified()
      throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    RecordingDocIdPusher pusher = new RecordingDocIdPusher();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.servers.server1.method", "ssl");
    configEntries.put("ad.defaultUser", "defaultUser");
    configEntries.put("ad.defaultPassword", "defaultPassword");
    configEntries.put("ad.groupSearchBaseDN", "ou=DoesNotMatter");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    Map<GroupPrincipal, Collection<Principal>> results =
        pusher.getGroupDefinitions();
    // the above (eventually) calls AdAdaptor.init() with the specified config.
  }

  @Test
  public void testFakeAdaptorInitThrowsExceptionWhenNoUserSpecified()
      throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.servers.server1.user", "");
    configEntries.put("ad.servers.server1.method", "ssl");
    try {
      initializeAdaptorConfig(adAdaptor, configEntries);
      fail("Did not catch expected exception");
    } catch (InvalidConfigurationException e) {
      assertTrue(e.toString().contains("user not specified"));
    }
  }

  @Test
  public void testFakeAdaptorInitThrowsExceptionWhenNoPasswordSpecified()
      throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.servers.server1.password", "");
    configEntries.put("ad.servers.server1.method", "ssl");
    configEntries.put("ad.defaultUser", "defaultUser");
    try {
      initializeAdaptorConfig(adAdaptor, configEntries);
      fail("Did not catch expected exception");
    } catch (InvalidConfigurationException e) {
      assertTrue(e.toString().contains("password not specified"));
    }
  }

  @Test
  public void testFakeAdaptorInitBadMethod() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.servers.server1.method", "https");
    configEntries.put("ad.defaultUser", "defaultUser");
    configEntries.put("ad.defaultPassword", "password");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    try {
      initializeAdaptorConfig(adAdaptor, configEntries);
      fail("Did not catch expected exception");
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.toString().contains("invalid method: https"));
    }
  }

  @Test
  public void testFakeAdaptorInitBadTimeout() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ad.servers", "server1");
    configEntries.put("ad.servers.server1.host", "localhost");
    configEntries.put("ad.servers.server1.port", "1234");
    configEntries.put("ad.defaultUser", "defaultUser");
    configEntries.put("ad.defaultPassword", "password");
    configEntries.put("ad.ldapReadTimeoutSecs", "bogus");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    try {
      initializeAdaptorConfig(adAdaptor, configEntries);
      fail("Did not catch expected exception");
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.toString().contains(
          "invalid value for ad.ldapReadTimeoutSecs"));
    }
  }

  @Test
  public void testFakeAdaptorGetDocIds() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    RecordingDocIdPusher pusher = new RecordingDocIdPusher();
    Map<String, String> configEntries = defaultConfig();
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    Map<GroupPrincipal, Collection<Principal>> results =
        pusher.getGroupDefinitions();

    final Map<GroupPrincipal, Collection<Principal>> goldenGroups =
        new HashMap<GroupPrincipal, Collection<Principal>>();
    {
      Principal everyone = new GroupPrincipal("Everyone", "Default");
      goldenGroups.put((GroupPrincipal) everyone, new ArrayList<Principal>());
      goldenGroups.put(new GroupPrincipal("sam@GSA-CONNECTORS", "Default"),
          new ArrayList<Principal>());
      goldenGroups.put(new GroupPrincipal("Authenticated Users@NT Authority",
          "Default"), Arrays.asList(everyone));
      goldenGroups.put(new GroupPrincipal("Interactive@NT Authority",
          "Default"), Arrays.asList(everyone));
    }
    assertEquals(goldenGroups, results);

    // make sure pushGroupDefinitions call is idempotent
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ false);
    results = pusher.getGroupDefinitions();
    assertEquals(goldenGroups, results);

    // even when doing an incremental push
    pushGroupDefinitions(adAdaptor, configEntries, pusher, /*fullPush=*/ false,
        /*init=*/ false);
    results = pusher.getGroupDefinitions();
    assertEquals(goldenGroups, results);
  }

  @Test
  public void testGetDocIdsExceptionPath() throws Exception {
    AdAdaptor adAdaptor = new AdAdaptor() {
      final String errorFilter = "(|(&(objectClass=group)"
          + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
          + "(&(objectClass=user)(objectCategory=person)))";
      @Override
      AdServer newAdServer(Method method, String host, int port,
          String principal, String passwd, String userSearchBaseDN,
          String groupSearchBaseDN, String userSearchFilter,
          String groupSearchFilter, String ldapTimeoutInMillis) {
        MockLdapContext ldapContext = null;
        try {
          ldapContext = mockLdapContextForMakeDefs(false);
        } catch (Exception e) {
          fail("Could not create LdapContext:" + e);
        }
        return new AdServer(host, userSearchBaseDN, groupSearchBaseDN,
            userSearchFilter, groupSearchFilter, ldapContext) {
          int timesSearchCalled = 0;
          int timesEnsureConnectionCalled = 0;
          @Override
          public Set<AdEntity> search(String baseDn, String filter,
              boolean deleted, String[] attributes)
              throws InterruptedNamingException {
            if (errorFilter.equals(filter) && timesSearchCalled++ == 0) {
              throw new InterruptedNamingException("First exception");
            } else {
              return super.search(baseDn, filter, deleted, attributes);
            }
          }
          @Override
          public void ensureConnectionIsCurrent()
              throws CommunicationException, NamingException {
            if (timesEnsureConnectionCalled++ < 9) {
              super.ensureConnectionIsCurrent();
            } else {
              throw new InterruptedNamingException("Second exception");
            }
          }
        };
      }
    };
    RecordingDocIdPusher pusher = new RecordingDocIdPusher();
    Map<String, String> configEntries = defaultConfig();
    try {
      pushGroupDefinitions(adAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
      fail("Did not catch expected IOException.");
    } catch (IOException ioe) {
      assertTrue(ioe.getCause().getMessage().equals("First exception"));
    }
    // repeat for getModifiedDocIds
    try {
      adAdaptor.clearLastCompleteGroupCatalog();
      pushGroupDefinitions(adAdaptor, configEntries, pusher,
          /*fullPush=*/ false, /*init=*/ true);
      fail("Did not catch expected IOException.");
    } catch (IOException ioe) {
      assertTrue(ioe.getCause().getMessage().equals("First exception"));
      boolean reachedLastCall = false;
      try {
        /* second call fills the catalog */
        pushGroupDefinitions(adAdaptor, configEntries, pusher,
            /*fullPush=*/ false, /*init=*/ false);
        /* third call does the push without any exception */
        pushGroupDefinitions(adAdaptor, configEntries, pusher,
            /*fullPush=*/ false, /*init=*/ false);
        reachedLastCall = true;
        /* last call redoes the push (and catches the second exception) */
        pushGroupDefinitions(adAdaptor, configEntries, pusher,
            /*fullPush=*/ false, /*init=*/ false);
        fail("Did not catch second expected IOException.");
      } catch (IOException ioe2) {
        assertTrue(ioe2.getCause().getMessage().equals("Second exception"));
        assertTrue(reachedLastCall);
      }
    }
  }

  public static byte[] hexStringToByteArray(String s) {
    return AdServerTest.hexStringToByteArray(s);
  }

  private static Map<String, String> defaultLocalizedStringMap() {
    Map<String, String> strings = new HashMap<String, String>();
    strings.put("Everyone", "Everyone");
    strings.put("NTAuthority", "NT Authority");
    strings.put("Interactive", "Interactive");
    strings.put("AuthenticatedUsers", "Authenticated Users");
    strings.put("Builtin", "BUILTIN");

    return strings;
  }

  private static Map<String, String> defaultConfig() {
    Map<String, String> strings = new HashMap<String, String>();
    strings.put("gsa.hostname", "localhost");
    strings.put("ad.servers", "server1");
    strings.put("ad.servers.server1.host", "localhost");
    strings.put("ad.defaultUser", "defaultUser");
    strings.put("ad.defaultPassword", "password");
    strings.put("server.port", "5680");
    strings.put("server.dashboardPort", "5681");

    return strings;
  }

  private MockLdapContext defaultMockLdapContext() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    // populate the attributes with values we can test
    ldapContext.addKey("defaultNamingContext", "DN_for_default_naming_context")
               .addKey("dsServiceName", "ds_service_name")
               .addKey("highestCommittedUSN", "12345678")
               .addKey("configurationNamingContext", "naming_context")
               .addSearchResult(
                 "distinguishedName=DN_for_default_naming_context",
                 "objectSid;binary",
                 "DN_for_default_naming_context",
                 hexStringToByteArray("010100000000000000000000")) // S-1-0-0
               .addSearchResult("distinguishedName=ds_service_name",
                 "invocationID;binary",
                 "ds_service_name",
                 hexStringToByteArray("000102030405060708090a0b0c"))
               .addSearchResult("(ncName=DN_for_default_naming_context)",
                 "nETBIOSName",
                 "naming_context",
                 "GSA-CONNECTORS");
    return ldapContext;
  }

  private MockLdapContext mockLdapContextForMakeDefs(boolean disableSamGroup)
      throws Exception {
    MockLdapContext ldapContext = defaultMockLdapContext();
    // add a group
    String filter = "(|(&(objectClass=group)"
        + "(groupType:1.2.840.113556.1.4.803:=2147483648))"
        + "(&(objectClass=user)(objectCategory=person)))";
    String searchDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("sid=null_FSP",
        "sid=S-1-5-21-411,cn=foreignsecurityprincipals,dc=resolved,dc=member",
        "sid=S-1-5-21-911,cn=foreignsecurityprincipals,dc=null,dc=resolution",
        "dn=user_dn,cn=user_name");
    ldapContext.addSearchResult(filter, "cn", searchDn, "group_name")
               .addSearchResult(filter, "objectSid;binary", searchDn,
                   hexStringToByteArray("010100000000000000000000")) // S-1-0-0
               .addSearchResult(filter, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter, "member", searchDn, members)
               .addSearchResult(filter, "userAccountControl", searchDn,
                   (disableSamGroup ? "514" : "512"))
               .addSearchResult(filter, "sAMAccountName", searchDn, "sam");
    // and a user (under another filter)
    String filter2 = "(&(objectClass=user)(objectCategory=person))";
    ldapContext.addSearchResult(filter2, "cn", searchDn, "group_name")
               .addSearchResult(filter2, "objectSid;binary", searchDn,
                                      // S-1-5-32-544: local Admin. group
                   hexStringToByteArray("01020000000000052000000020020000"))
               .addSearchResult(filter2, "objectGUID;binary", searchDn,
                   hexStringToByteArray("000102030405060708090a0b0e"))
               .addSearchResult(filter2, "primaryGroupId", searchDn, "users")
               .addSearchResult(filter2, "sAMAccountName", searchDn, "sam2");

    return ldapContext;
  }

  private void tweakGroupCatalogForMakeDefs(AdAdaptor.GroupCatalog groupCatalog,
      AdServer adServer, boolean disableSamGroup) throws Exception {
    // add two additional entities to test all branches of our method.
    assertEquals(1, groupCatalog.entities.size());
    // first -- a user
    Set<AdEntity> userEntity = adServer.search("",
        "(&(objectClass=user)(objectCategory=person))", false,
        new String[] { "cn", "objectSid;binary", "objectGUID;binary",
            "primaryGroupId", "sAMAccountName" });

    assertEquals(1, userEntity.size());
    for (AdEntity ae : userEntity) {
      assertFalse(ae.isGroup());
      groupCatalog.entities.add(ae);
      groupCatalog.bySid.put("S-1-5-21-411", ae);
      groupCatalog.byDn.put("dn=user_dn,cn=user_name", ae);
    }
    // lastly -- two well known Entities, one of which is a known group.
    AdEntity wellKnownEntity = new AdEntity("S-1-5-32-1", "dn=BUILTIN");
    assertTrue(wellKnownEntity.isWellKnown());
    groupCatalog.entities.add(wellKnownEntity);
    AdEntity knownGroup = new AdEntity("S-1-5-32-2", "dn=known_group");
    groupCatalog.entities.add(knownGroup);
    groupCatalog.members.put(knownGroup, new TreeSet<String>());
    groupCatalog.byDn.put(
        "sid=S-1-5-21-411,cn=foreignsecurityprincipals,dc=resolved,dc=member",
        knownGroup);
  }

  /**
   * Clears the catalog, and then restores wellKnownMembership to a usable
   * state (so that a call to <code>add()</code> won't blow up with a
   * <code>NullPointerException</code>.
   */
  private void almostClear(AdAdaptor.GroupCatalog catalog) {
    catalog.clear();
    catalog.wellKnownMembership.put(catalog.everyone, new TreeSet<String>());
    catalog.wellKnownMembership.put(catalog.interactive, new TreeSet<String>());
    catalog.wellKnownMembership.put(catalog.authenticatedUsers,
        new TreeSet<String>());
  }

  /**
   * Copied in from TestHelper (from the library)
   */
  public static void initializeAdaptorConfig(Adaptor adaptor,
      Map<String, String> configEntries) throws Exception {
    final Config config = new Config();
    adaptor.initConfig(config);
    for (Map.Entry<String, String> entry : configEntries.entrySet()) {
      TestHelper.setConfigValue(config, entry.getKey(), entry.getValue());
    }
    adaptor.init(TestHelper.createConfigAdaptorContext(config));
  }

  public static void pushGroupDefinitions(AdAdaptor adaptor,
      Map<String, String> configEntries, final DocIdPusher pusher,
      boolean fullPush, boolean init) throws Exception {
    if (init) {
      initializeAdaptorConfig(adaptor, configEntries);
    }
    if (fullPush) {
      adaptor.getDocIds(pusher);
    } else {
      adaptor.getModifiedDocIds(pusher);
    }
  }

  /** A version of AdAdaptor that uses only mock AdServers */
  public class FakeAdaptor extends AdAdaptor {
    @Override
    AdServer newAdServer(Method method, String host, int port,
        String principal, String passwd, String userSearchBaseDN,
        String groupSearchBaseDN, String userSearchFilter,
        String groupSearchFilter, String ldapTimeoutInMillis) {
      MockLdapContext ldapContext = null;
      try {
        ldapContext = mockLdapContextForMakeDefs(false);
      } catch (Exception e) {
        fail("Could not create LdapContext:" + e);
      }
      return new AdServer(host, userSearchBaseDN, groupSearchBaseDN,
          userSearchFilter, groupSearchFilter, ldapContext) {
        private long highestCommittedUSN = 12345678;
        @Override
        void recreateLdapContext() {
          // leave ldapContext unchanged
        }
        @Override
        public long getHighestCommittedUSN() {
          // always indicate new items available to sync
          return ++highestCommittedUSN;
        }
      };
    }
    @Override
    void getModifiedDocIdsHelper(DocIdPusher pusher)
        throws InterruptedException, IOException {
      // do nothing
    }
  };

  /**
   * A version of AdAdaptor that shares one MockLdapContext object between
   * multiple (mock) AdServers.
   */
  public class FakeAdaptorWithSharedMockLdapContext extends AdAdaptor {
    private final MockLdapContext sharedLdapContext;

    public FakeAdaptorWithSharedMockLdapContext(MockLdapContext ldapContext) {
      sharedLdapContext = ldapContext;
    }
    @Override
    AdServer newAdServer(Method method, String host, int port,
        String principal, String passwd, String userSearchBaseDN,
        String groupSearchBaseDN, String userSearchFilter,
        String groupSearchFilter, String ldapTimeoutInMillis) {
      MockLdapContext ldapContext = sharedLdapContext;
      return new AdServer(host, userSearchBaseDN, groupSearchBaseDN,
          userSearchFilter, groupSearchFilter, ldapContext) {
        @Override
        void recreateLdapContext() {
          // leave ldapContext unchanged
        }
      };
    }
    @Override
    void getModifiedDocIdsHelper(DocIdPusher pusher)
        throws InterruptedException, IOException {
      // do nothing
    }
  };

  /** Simple Fake of GroupCatalog that tracks calls to full/incremental crawl */
  private static class FakeCatalog extends AdAdaptor.GroupCatalog {
    private boolean ranFullCrawl;
    private boolean ranIncrementalCrawl;

    public FakeCatalog(Map<String, String> localizedStrings, String namespace,
        boolean feedBuiltinGroups) {
      super(localizedStrings, namespace, feedBuiltinGroups);
    }

    @Override
    void readEverythingFrom(AdServer server, boolean unused)
        throws InterruptedNamingException {
      try {
        Thread.sleep(BRIEF_DELAY_IN_MILLISECONDS * 2);
      } catch (InterruptedException ex) {
        throw new InterruptedNamingException(ex.getMessage());
      }
      ranFullCrawl = true;
    }

    @Override
    Set<AdEntity> incrementalCrawl(AdServer server, long previousHighestUSN,
        long currentHighestUSN) throws InterruptedNamingException {
      try {
        Thread.sleep(BRIEF_DELAY_IN_MILLISECONDS * 2);
      } catch (InterruptedException ex) {
        throw new InterruptedNamingException(ex.getMessage());
      }
      ranIncrementalCrawl = true;
      return Collections.emptySet();
    }

    void resetCrawlFlags() {
      ranFullCrawl = false;
      ranIncrementalCrawl = false;
    }

    public boolean ranIncrementalCrawl() {
      return ranIncrementalCrawl;
    }

    public boolean ranFullCrawl() {
      return ranFullCrawl;
    }
  }

  /** An even "faker" version of AdAdaptor that only tests the mutex */
  public class MoreFakeAdaptor extends FakeAdaptor {
    private boolean ranFullCrawl;
    private boolean ranIncrementalCrawl;

    void resetCrawlFlags() {
      ranFullCrawl = false;
      ranIncrementalCrawl = false;
    }

    public boolean ranIncrementalCrawl() {
      return ranIncrementalCrawl;
    }

    public boolean ranFullCrawl() {
      return ranFullCrawl;
    }

    @Override
    void getModifiedDocIdsHelper(DocIdPusher pusher)
        throws InterruptedException, IOException {
      ranIncrementalCrawl = true;
    }

    @Override
    AdAdaptor.GroupCatalog makeFullCatalog() throws InterruptedException,
        IOException {
      try {
        Thread.sleep(BRIEF_DELAY_IN_MILLISECONDS * 2);
      } catch (InterruptedException ex) {
        throw new RuntimeException(ex);
      }
      ranFullCrawl = true;
      return new AdAdaptor.GroupCatalog(defaultLocalizedStringMap(),
          "example.com", /*feedBuiltinGroups=*/ true);
    }
  };

  /** generates a thread that invokes a (fake!) full crawl */
  private static class FullCrawlThread extends Thread {
    FullCrawlThread (final AdAdaptor adAdaptor) {
      super((new Runnable() {
        @Override
        public void run() {
          try {
            RecordingDocIdPusher pusher = new RecordingDocIdPusher();
            adAdaptor.getDocIds(pusher);
          } catch (Exception ex) {
            throw new RuntimeException(ex);
          }
        }
      }));
    }
  }

  /** generates a thread that invokes a (fake!) incremental crawl */
  private static class IncrementalCrawlThread extends Thread {
    IncrementalCrawlThread (final AdAdaptor adAdaptor) {
      super((new Runnable() {
        @Override
        public void run() {
          try {
            RecordingDocIdPusher pusher = new RecordingDocIdPusher();
            adAdaptor.getModifiedDocIds(pusher);
          } catch (Exception ex) {
            throw new RuntimeException(ex);
          }
        }
      }));
    }
  }

  private static class GroupCatalogBuilder {
    private Map<String, String> localizedStrings = defaultLocalizedStringMap();
    private String namespace = "example.com";
    private boolean feedBuiltinGroups = false;
    private Set<AdEntity> entities;
    private Map<AdEntity, Set<String>> members;
    private Map<AdEntity, Set<String>> primaryMembers;
    private Map<String, AdEntity> bySid;
    private Map<String, AdEntity> byDn;
    private Map<AdEntity, String> domain;
    /**
     * The following field is only used by this Builder class, to determine if
     * the build() method should call the standard constructor or the extended
     * constructor.
     */
    private boolean useExtendedConstructor = false;

    public GroupCatalogBuilder setLocalizedStrings(Map<String, String> locals) {
      this.localizedStrings = locals;
      return this;
    }

    public GroupCatalogBuilder setNamespace(String namespace) {
      this.namespace = namespace;
      return this;
    }

    public GroupCatalogBuilder setFeedBuiltinGroups(boolean feedBuiltinGroups) {
      this.feedBuiltinGroups = feedBuiltinGroups;
      return this;
    }

    // The remaining fields are the "extended" fields -- their setters set the
    // variable as well as the flag to use the extended constructor.

    public GroupCatalogBuilder setEntities(Set<AdEntity> entities) {
      this.entities = entities;
      this.useExtendedConstructor = true;
      return this;
    }

    public GroupCatalogBuilder setMembers(Map<AdEntity, Set<String>> members) {
      this.members = members;
      this.useExtendedConstructor = true;
      return this;
    }

    public GroupCatalogBuilder setPrimaryMembers(Map<AdEntity,
        Set<String>> primaryMembers) {
      this.primaryMembers = primaryMembers;
      this.useExtendedConstructor = true;
      return this;
    }

    public GroupCatalogBuilder setBySid(Map<String, AdEntity> bySid) {
      this.bySid = bySid;
      this.useExtendedConstructor = true;
      return this;
    }

    public GroupCatalogBuilder setByDn(Map<String, AdEntity> byDn) {
      this.byDn = byDn;
      this.useExtendedConstructor = true;
      return this;
    }

    public GroupCatalogBuilder setDomain(Map<AdEntity, String> domain) {
      this.domain = domain;
      this.useExtendedConstructor = true;
      return this;
    }

    public AdAdaptor.GroupCatalog build() {
      if (useExtendedConstructor) {
        return new AdAdaptor.GroupCatalog(localizedStrings, namespace,
            feedBuiltinGroups, entities, members, primaryMembers, bySid, byDn,
            domain);
      }
      return new AdAdaptor.GroupCatalog(localizedStrings, namespace,
          feedBuiltinGroups);
    }
  }
}
