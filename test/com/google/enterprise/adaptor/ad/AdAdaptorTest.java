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

import static org.junit.Assert.*;

import com.google.common.collect.Sets;

import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Adaptor;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.TestHelper;
import com.google.enterprise.adaptor.UserPrincipal;

import org.junit.Test;

import java.io.*;
import java.net.URI;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;

/** Test cases for {@link AdAdaptor}. */
public class AdAdaptorTest {
  @Test
  public void testNoop() {
  }

  @Test
  public void testGroupCatalogConstructor() {
    Map<String, String> strings = defaultLocalizedStringMap();

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ false);
    final AdAdaptor.GroupCatalog golden = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ true);
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogEquals() {
    Map<String, String> strings = defaultLocalizedStringMap();
    final AdAdaptor.GroupCatalog golden = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ true);
    golden.members.put(new AdEntity("Test", "dn=Test"),
        Sets.newHashSet("Test"));
    final Map<AdEntity, Set<String>> goldenWellKnownMembership =
        golden.wellKnownMembership;

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ false);
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
  }

  @Test
  public void testGroupCatalogReadFrom() throws Exception {
    Map<String, String> strings = defaultLocalizedStringMap();

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ false);
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

    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.readFrom(adServer);

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

    final AdAdaptor.GroupCatalog golden = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ true,
      /*entities*/ Sets.newHashSet(goldenEntity),
      /*members*/ goldenMembers,
      /*bySid*/ goldenSid,
      /*byDn*/ goldenDn,
      /*domain*/ goldenDomain);

    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogReadFromReturnsDisabledGroup() throws Exception {
    Map<String, String> strings = defaultLocalizedStringMap();

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ false);
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

    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.readFrom(adServer);

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

    final AdAdaptor.GroupCatalog golden = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ true,
      /*entities*/ Sets.newHashSet(goldenEntity),
      /*members*/ goldenMembers,
      /*bySid*/ goldenSid,
      /*byDn*/ goldenDn,
      /*domain*/ goldenDomain);

    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogReadFromReturnsUser() throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
        defaultLocalizedStringMap(), "example", /*feedBuiltinGroups=*/ false);
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
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.bySid.put("S-1-5-32-users", userGroup);
    groupCatalog.readFrom(adServer);

    final AdEntity goldenEntity = new AdEntity("S-1-5-32-544",
        "cn=name\\ under,DN_for_default_naming_context", "users", "sam");
    final Map<AdEntity, Set<String>> goldenMembers =
        new HashMap<AdEntity, Set<String>>();
    goldenMembers.put(userGroup, Sets.newHashSet(goldenEntity.getDn()));
    final Map<String, AdEntity> goldenSid = new HashMap<String, AdEntity>();
    goldenSid.put("S-1-5-32-users", userGroup);
    goldenSid.put("S-1-5-32-544", goldenEntity);
    final Map<String, AdEntity> goldenDn = new HashMap<String, AdEntity>();
    goldenDn.put(goldenEntity.getDn(), goldenEntity);
    final Map<AdEntity, String> goldenDomain = new HashMap<AdEntity, String>();
    goldenDomain.put(goldenEntity, "BUILTIN");

    final AdAdaptor.GroupCatalog golden = new AdAdaptor.GroupCatalog(
      defaultLocalizedStringMap(), "example.com", /*feedBuiltinGroups=*/ true,
      /*entities*/ Sets.newHashSet(goldenEntity),
      /*members*/ goldenMembers,
      /*bySid*/ goldenSid,
      /*byDn*/ goldenDn,
      /*domain*/ goldenDomain);

    assertTrue(golden.equals(groupCatalog));

    // make sure readFrom call is idempotent
    groupCatalog.readFrom(adServer);
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogReadFromReturnsUserMissingPrimaryGroup()
      throws Exception {
    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
        defaultLocalizedStringMap(), "example", /*feedBuiltinGroups=*/ false);
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

    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.readFrom(adServer);

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

    final AdAdaptor.GroupCatalog golden = new AdAdaptor.GroupCatalog(
      defaultLocalizedStringMap(), "example.com", /*feedBuiltinGroups=*/ true,
      /*entities*/ Sets.newHashSet(goldenEntity),
      /*members*/ goldenMembers,
      /*bySid*/ goldenSid,
      /*byDn*/ goldenDn,
      /*domain*/ goldenDomain);

    assertTrue(golden.equals(groupCatalog));

    // make sure readFrom call is idempotent
    groupCatalog.readFrom(adServer);
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogResolveForeignSecurityPrincipals()
      throws Exception {
    Map<String, String> strings = defaultLocalizedStringMap();

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ false);
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

    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.readFrom(adServer);

    // add two additional entities to test all branches of our method.
    // first -- a user
    Set<AdEntity> userEntitySet = adServer.search(filter2, false,
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

    groupCatalog.resolveForeignSecurityPrincipals();

    // extract original group entity
    Set<AdEntity> groupEntitySet = adServer.search(filter, false,
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
    final AdAdaptor.GroupCatalog golden = new AdAdaptor.GroupCatalog(
      defaultLocalizedStringMap(), "example.com", /*feedBuiltinGroups=*/ true,
      /*entities*/ goldenEntities,
      /*members*/ goldenMembers,
      /*bySid*/ goldenSid,
      /*byDn*/ goldenDn,
      /*domain*/ goldenDomain);

    assertTrue(golden.equals(groupCatalog));

    // make sure readFrom call is idempotent
    groupCatalog.resolveForeignSecurityPrincipals();
    assertTrue(golden.equals(groupCatalog));
  }

  @Test
  public void testGroupCatalogMakeDefs() throws Exception {
    Map<String, String> strings = defaultLocalizedStringMap();

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ false);

    MockLdapContext ldapContext = mockLdapContextForMakeDefs(false);

    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.readFrom(adServer);

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
    assertEquals(golden, groupCatalog.makeDefs());
  }

  @Test
  public void testGroupCatalogMakeDefsWithDisabledGroup() throws Exception {
    Map<String, String> strings = defaultLocalizedStringMap();

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ false);

    MockLdapContext ldapContext = mockLdapContextForMakeDefs(true);

    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.readFrom(adServer);

    tweakGroupCatalogForMakeDefs(groupCatalog, adServer, true);

    final Map<GroupPrincipal, List<Principal>> golden =
        new HashMap<GroupPrincipal, List<Principal>>();
    {
      golden.put(new GroupPrincipal("sam@GSA-CONNECTORS", "example.com"),
          Collections.<Principal>emptyList());
      golden.put(new GroupPrincipal("known_group", "example.com"),
          Collections.<Principal>emptyList());
    }
    assertEquals(golden, groupCatalog.makeDefs());
  }

  @Test
  public void testGroupCatalogMakeDefsWellKnownParent() throws Exception {
    Map<String, String> strings = defaultLocalizedStringMap();

    AdAdaptor.GroupCatalog groupCatalog = new AdAdaptor.GroupCatalog(
      strings, "example.com", /*feedBuiltinGroups=*/ true);
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

    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();

    groupCatalog.readFrom(adServer);

    tweakGroupCatalogForMakeDefs(groupCatalog, adServer, false);
    // now replace the parent group with a well-known one
    AdEntity replacementGroup = new AdEntity("S-1-0-0", "dn=new_parent");
    AdEntity groupWithNoName = new AdEntity("", "dn=");
    AdEntity formerGroup = null;
    for (AdEntity entity : groupCatalog.entities) {
      if ("cn=name\\ under,DN_for_default_naming_context".equals(entity.getDn())
          && (entity.getMembers().size() == 4)) {
        formerGroup = entity;
        for (String member: entity.getMembers()) {
          replacementGroup.getMembers().add(member);
        }
        // trigger the IllegalArgumentException paths by adding empty-named
        // members to the results
        groupCatalog.byDn.put("dn=", groupWithNoName);
        replacementGroup.getMembers().add("dn=");
        groupCatalog.members.put(groupWithNoName, new TreeSet<String>());

        Set<AdEntity> emptyUser = adServer.search(filter, false,
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
    assertEquals(golden, groupCatalog.makeDefs());
  }

  // Tests for the methods of the outer class

  @Test
  public void testFakeAdaptorGetDocContent() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    MockResponse mockResponse = new MockResponse();
    adAdaptor.getDocContent(null, mockResponse);
    assertTrue(mockResponse.wasRespondNotFoundCalled());
  }

  @Test
  public void testFakeAdaptorInit() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
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
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    pushGroupDefinitions(adAdaptor, configEntries, pusher);
    Map<GroupPrincipal, Collection<Principal>> results = pusher.getGroups();
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
    } catch (IllegalStateException e) {
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
    } catch (IllegalStateException e) {
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
    } catch (IllegalArgumentException iae) {
      assertTrue(iae.toString().contains("invalid method: https"));
    }
  }

  @Test
  public void testFakeAdaptorGetDocIds() throws Exception {
    AdAdaptor adAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfig();
    pushGroupDefinitions(adAdaptor, configEntries, pusher);
    Map<GroupPrincipal, Collection<Principal>> results = pusher.getGroups();

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
    pushGroupDefinitions(adAdaptor, configEntries, pusher);
    results = pusher.getGroups();
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
          String principal, String passwd) {
        MockLdapContext ldapContext = null;
        try {
          ldapContext = mockLdapContextForMakeDefs(false);
        } catch (Exception e) {
          fail("Could not create LdapContext:" + e);
        }
        return new AdServer(host, ldapContext) {
          @Override
          public Set<AdEntity> search(String filter, boolean deleted,
              String[] attributes) throws InterruptedNamingException {
            if (errorFilter.equals(filter)) {
              throw new InterruptedNamingException("Catch me if you can!");
            } else {
              return super.search(filter, deleted, attributes);
            }
          }
          @Override
          void recreateLdapContext() {
            // leave ldapContext unchanged
          }
        };
      }
    };
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfig();
    try {
      pushGroupDefinitions(adAdaptor, configEntries, pusher);
      fail("Did not catch expected IOException.");
    } catch (IOException ioe) {
      assertTrue(ioe.getCause().getMessage().equals("Catch me if you can!"));
    }
  }


  public static byte[] hexStringToByteArray(String s) {
    return AdServerTest.hexStringToByteArray(s);
  }

  private Map<String, String> defaultLocalizedStringMap() {
    Map<String, String> strings = new HashMap<String, String>();
    strings.put("Everyone", "everyone");
    strings.put("NTAuthority", "NT Authority");
    strings.put("Interactive", "Interactive");
    strings.put("AuthenticatedUsers", "Authenticated Users");
    strings.put("Builtin", "BUILTIN");

    return strings;
  }

  private Map<String, String> defaultConfig() {
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
    Set<AdEntity> userEntity = adServer.search(
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

  /**
   * Copied in from TestHelper (from the library)
   */
  public static void pushGroupDefinitions(Adaptor adaptor,
      Map<String, String> configEntries, final DocIdPusher pusher)
      throws Exception {
    initializeAdaptorConfig(adaptor, configEntries);
    adaptor.getDocIds(pusher);
  }

  /**
   * Used to make sure nothing but responseNotFound() is called
   */
  public static class MockResponse implements Response {
    private boolean respondNotFoundCalled = false;

    public boolean wasRespondNotFoundCalled() {
      return respondNotFoundCalled;
    }

    @Override
    public void respondNotModified() throws IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public void respondNotFound() throws IOException {
      if (respondNotFoundCalled) {
        throw new AssertionError("respondNotFound() called twice");
      }
      respondNotFoundCalled = true;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setContentType(String contentType) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setLastModified(Date lastModified) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void addMetadata(String key, String value) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setAcl(Acl acl) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void putNamedResource(String fname, Acl facl) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setSecure(boolean secure) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void addAnchor(URI uri, String text) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setNoIndex(boolean noIndex) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setNoFollow(boolean noFollow) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setNoArchive(boolean noArchive) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setDisplayUrl(URI displayUrl) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setCrawlOnce(boolean crawlOnce) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setLock(boolean lock) {
      throw new UnsupportedOperationException();
    }
  }

  /** A version of AdAdaptor that uses only mock AdServers */
  public class FakeAdaptor extends AdAdaptor {
    @Override
    AdServer newAdServer(Method method, String host, int port,
        String principal, String passwd) {
      MockLdapContext ldapContext = null;
      try {
        ldapContext = mockLdapContextForMakeDefs(false);
      } catch (Exception e) {
        fail("Could not create LdapContext:" + e);
      }
      return new AdServer(host, ldapContext) {
        @Override
        void recreateLdapContext() {
          // leave ldapContext unchanged
        }
      };
    }
  }
}
