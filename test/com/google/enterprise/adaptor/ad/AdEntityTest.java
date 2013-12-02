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

import org.junit.Test;

import java.util.*;

import javax.naming.directory.*;

/** Test cases for {@link AdEntity}. */
public class AdEntityTest {
  @Test
  public void testStandardConstructor() throws Exception {
    Attributes attrs = new BasicAttributes();
    attrs.put("objectGUID;binary",
        AdServerTest.hexStringToByteArray("000102030405060708090a0b0c"));
    attrs.put("objectSid;binary", // S-1-0-0
        AdServerTest.hexStringToByteArray("010100000000000000000000"));
    attrs.put("uSNChanged", "12345678");
    attrs.put("primaryGroupId", "users");

    SearchResult sr = new SearchResult("SR name", attrs, attrs);
    sr.setNameInNamespace("cn=user,ou=Users,dc=example,dc=com");
    AdEntity adEntity = new AdEntity(sr);
    assertEquals("user", adEntity.getCommonName());
    assertEquals("S-1-0-0", adEntity.getSid());
    assertEquals("cn=user,ou=Users,dc=example,dc=com", adEntity.getDn());
    assertFalse(adEntity.isWellKnown());
    assertEquals(0, adEntity.getMembers().size());
    assertEquals("S-1-0-users", adEntity.getPrimaryGroupSid());
  }

  @Test
  public void testWellKnownConstructor() throws Exception {
    AdEntity adEntity = new AdEntity("S-1-1-1",
        "dn=escaped\\,cn=users,ou=Users,dc=example,dc=com");
    assertEquals("escaped,cn=users", adEntity.getCommonName());
    assertEquals("S-1-1-1", adEntity.getSid());
    assertEquals("dn=escaped\\,cn=users,ou=Users,dc=example,dc=com",
        adEntity.getDn());
    assertTrue(adEntity.isWellKnown());
    assertEquals(0, adEntity.getMembers().size());
  }

  @Test
  public void testWellKnownConstructorNoCommaInDN() throws Exception {
    AdEntity adEntity = new AdEntity("NoComma", "dc=com");
    assertEquals("com", adEntity.getCommonName());
    assertEquals("dc=com", adEntity.getDn());
    assertTrue(adEntity.isWellKnown());
  }

  @Test
  public void testWellKnownConstructorTrailingComma() throws Exception {
    AdEntity adEntity = new AdEntity("NoComma", "dc=com,");
    assertEquals("com", adEntity.getCommonName());
    assertEquals("dc=com,", adEntity.getDn());
    assertTrue(adEntity.isWellKnown());
  }

  @Test
  public void testAppendGroupsOnEmptyGroup() throws Exception {
    AdEntity adEntity = new AdEntity("parentGroup", "dc=com");

    Attributes attrs = new BasicAttributes();
    attrs.put("objectGUID;binary",
        AdServerTest.hexStringToByteArray("000102030405060708090a0b0c"));
    attrs.put("objectSid;binary", // S-1-0-0
        AdServerTest.hexStringToByteArray("010100000000000000000000"));
    attrs.put("member", null);
    Attribute memberAttr = attrs.get("member");
    memberAttr.clear();
    SearchResult sr = new SearchResult("subgroup", attrs, attrs);
    sr.setNameInNamespace("cn=subgroup,ou=Groups,dc=example,dc=com");
    AdEntity ae = new AdEntity(sr);

    HashSet<String> expectedMembers = new HashSet<String>();
    assertEquals(expectedMembers, ae.getMembers());
    assertEquals(0, adEntity.appendGroups(sr));
  }

  @Test
  public void testAppendGroupsOnRealGroup() throws Exception {
    AdEntity adEntity = new AdEntity("parentGroup", "dc=com");

    Attributes attrs = new BasicAttributes();
    attrs.put("objectGUID;binary",
        AdServerTest.hexStringToByteArray("000102030405060708090a0b0c"));
    attrs.put("objectSid;binary", // S-1-0-0
        AdServerTest.hexStringToByteArray("010100000000000000000000"));
    List<String> members = Arrays.asList("dn_for_user_1", "dn_for_user_2");
    attrs.put("member", null);
    Attribute memberAttr = attrs.get("member");
    memberAttr.clear();
    for (String member: members) {
      memberAttr.add(member);
    }

    SearchResult sr = new SearchResult("subgroup", attrs, attrs);
    sr.setNameInNamespace("cn=subgroup,ou=Groups,dc=example,dc=com");
    AdEntity ae = new AdEntity(sr);

    assertEquals(new HashSet<String>(members), ae.getMembers());
    assertEquals(2, adEntity.appendGroups(sr));
  }

  @Test
  public void testParseForeignSecurityPrincipal() throws Exception {
    AdEntity adEntity = new AdEntity("NoComma", "dc=com");
    assertNull(adEntity.parseForeignSecurityPrincipal(""));
    assertNull(adEntity.parseForeignSecurityPrincipal(
        "cn=foreignsecurityprincipals,dc=example,dc=com"));
    String validSid = "S-1-5-21-42";
    assertEquals(validSid, adEntity.parseForeignSecurityPrincipal(
        "id=" + validSid + ",cn=foreignsecurityprincipals,dc=example,dc=com"));
  }
}
