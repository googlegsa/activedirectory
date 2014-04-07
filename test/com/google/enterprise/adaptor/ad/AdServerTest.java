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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;

import java.util.*;

/** Test cases for {@link AdServer}. */
public class AdServerTest {
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testStandardServer() throws Exception {
    AdServer adServer = new AdServer("hostname", new MockLdapContext());
    assertEquals("hostname", adServer.getHostName());
  }

  @Test
  public void testNPEOnNullConnectMethod() {
    thrown.expect(NullPointerException.class);
    AdServer adServer = new AdServer(null, "hostname", 1234, "principal", "pw",
        "90000");
  }

  @Test
  public void testNPEOnNullHostname() {
    thrown.expect(NullPointerException.class);
    AdServer adServer = new AdServer(Method.SSL, null, 1234, "principal", "pw",
        "90000");
  }

  @Test
  public void testIAEOnEmptyHostname() {
    thrown.expect(IllegalArgumentException.class);
    AdServer adServer = new AdServer(Method.SSL, "", 1234, "principal", "pw",
        "90000");
  }

  @Test
  public void testNPEOnNullPrincipal() {
    thrown.expect(NullPointerException.class);
    AdServer adServer = new AdServer(Method.SSL, "hostname", 1234, null, "pw",
        "90000");
  }

  @Test
  public void testIAEOnEmptyPrincipal() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    AdServer adServer = new AdServer(Method.SSL, "hostname", 1234, "", "pw",
        "90000");
  }

  @Test
  public void testNPEOnNullPassword() {
    thrown.expect(NullPointerException.class);
    AdServer adServer = new AdServer(Method.SSL, "host", 1234, "princ", null,
        "90000");
  }

  @Test
  public void testIAEOnEmptyPassword() {
    thrown.expect(IllegalArgumentException.class);
    AdServer adServer = new AdServer(Method.SSL, "hostname", 1234, "princ", "",
        "90000");
  }

  @Test
  public void testIAEOnBogusTimeout() {
    thrown.expect(IllegalArgumentException.class);
    AdServer adServer = new AdServer(Method.SSL, "", 1234, "principal", "pw",
        "bogusTimeout");
  }

  @Test
  public void testPublicSSLConstructor() {
    thrown.expect(AssertionError.class);
    AdServer adServer = new AdServer(Method.SSL, "localhost", 389, " ", " ",
        "90000");
  }

  @Test
  public void testPublicStandardConstructor() {
    thrown.expect(AssertionError.class);
    AdServer adServer =
        new AdServer(Method.STANDARD, "localhost", 389, " ", " ", "90000");
  }

  @Test
  public void testStandardServerInitialize() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    ldapContext.addSearchResult("dn=empty", "empty", "empty", "")
               .addSearchResult("dn=empty", "attr1", "basedn", "val1");
    AdServer adServer = new AdServer("localhost", ldapContext);
    assertEquals("localhost", adServer.getHostName());
    adServer.initialize();
    assertEquals("DN_for_default_naming_context", adServer.getDn());
    assertEquals("ds_service_name", adServer.getDsServiceName());
    assertEquals(12345678L, adServer.getHighestCommittedUSN());
    assertEquals("S-1-0-0", adServer.getSid());
    assertEquals("0x0123456789abc", adServer.getInvocationID());
    assertEquals("GSA-CONNECTORS", adServer.getnETBIOSName());
    assertEquals("[GSA-CONNECTORS] ", adServer.toString());
    assertEquals("", adServer.get("dn=empty", "empty", "empty"));
    assertNull(adServer.get("dn=ds_service_name", "null", "null"));
    assertEquals("val1", adServer.get("dn=empty", "attr1", "basedn"));
    assertNull(adServer.get("dn=empty", "attr2", "basedn"));
  }

  @Test
  /*
   * This tests a code path that the author doesn't think can actually happen
   *
   * <p> where <code>ldapResults</code> is not <code>null</code>, but where
   * <code>attrs.get(attribute)</code> does return <code>null</code>.
   */
  public void testGetNotReturningAttribute() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public NamingEnumeration<SearchResult> search(String base, String filter,
        SearchControls searchControls) throws NamingException {
        if (!("dn=empty".equals(filter))) {
          return super.search(base, filter, searchControls);
        }
        // prepare "broken" SearchResult
        Vector<SearchResult> brokenSRs = new Vector<SearchResult>();
        brokenSRs.add(new SearchResult("search result name", brokenSRs,
            new BasicAttributes()));
        return new MockLdapContext.SearchResultsNamingEnumeration(brokenSRs);
      }
    };
    addStandardKeysAndResults(ldapContext);
    ldapContext.addSearchResult("dn=empty", "attr1", "basedn", "val1");
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    assertNull(adServer.get("dn=empty", "attr1", "basedn"));
  }

  @Test
  public void testGetThrowsNamingException() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public NamingEnumeration<SearchResult> search(String base, String filter,
        SearchControls searchControls) throws NamingException {
        if (!("dn=empty".equals(filter))) {
          return super.search(base, filter, searchControls);
        }
        throw new NamingException("Gotcha");
      }
    };
    addStandardKeysAndResults(ldapContext);
    ldapContext.addSearchResult("dn=empty", "attr1", "basedn", "val1");
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    assertNull(adServer.get("dn=empty", "attr1", "basedn"));
  }

  @Test
  public void testConnectThrowsNamingException() throws Exception {
    thrown.expect(RuntimeException.class);
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        throw new NamingException("Can't connect");
      }
    };
    addStandardKeysAndResults(ldapContext);
    ldapContext.addSearchResult("dn=empty", "attr1", "basedn", "val1");
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
  }

  @Test
  public void testEnsureOnetimeException() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      boolean firstTime = true;
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        if (firstTime) {
          firstTime = false;
          throw new CommunicationException("testing");
        } else {
          return super.getAttributes(name);
        }
      }
    };
    addStandardKeysAndResults(ldapContext);
    AdServer adServer = new AdServer("localhost", ldapContext) {
      @Override
      void recreateLdapContext() {
        // do nothing
      }
    };
    adServer.initialize();
  }

  @Test
  public void testEnsureConnectionTimesOut() throws Exception {
    thrown.expect(RuntimeException.class);
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        throw new NamingException("read timed out");
      }
    };
    addStandardKeysAndResults(ldapContext);
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
  }

  @Test
  public void testSearchReturnsOneUser() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String userDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", userDn, "user1")
               .addSearchResult(filter, "primaryGroupId", userDn, "users")
               .addSearchResult(filter, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"));
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, false,
        new String[] { "cn", "primaryGroupId", "objectGUID;binary" });
    assertEquals(1, resultSet.size());
    for (AdEntity ae : resultSet) {
      assertEquals("name under", ae.getCommonName());
    }
  }

  @Test
  public void testSearchReturnsNoUsersWhenMissingGUID() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String userDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", userDn, "user1")
               .addSearchResult(filter, "primaryGroupId", userDn, "users");
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, false,
        new String[] { "cn", "primaryGroupId", "objectGUID;binary" });
    assertEquals(0, resultSet.size());
  }

  @Test
  public void testSetControlsThrowsException() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public void setRequestControls(Control[] requestControls)
          throws NamingException {
        controls = requestControls;
        throw new NamingException("testing exception path");
      }
    };
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String userDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", userDn, "user1")
               .addSearchResult(filter, "primaryGroupId", userDn, "users");
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, false,
        new String[] { "cn", "primaryGroupId", "objectGUID;binary" });
    assertEquals(0, resultSet.size());
  }

  @Test
  public void testSearchReturnsOneDeletedUser() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String userDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", userDn, "user1")
               .addSearchResult(filter, "primaryGroupId", userDn, "users")
               .addSearchResult(filter, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"));
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, true,
        new String[] { "cn", "primaryGroupId", "objectGUID;binary" });
    assertEquals(1, resultSet.size());
    for (AdEntity ae : resultSet) {
      assertEquals("name under", ae.getCommonName());
    }
    // now verify the DeletedControl is exactly as we expect
    assertEquals(2, ldapContext.getResponseControls().length);
    Control deletedControl = ldapContext.getResponseControls()[1];
    assertArrayEquals(new byte[0], deletedControl.getEncodedValue());
    assertEquals("1.2.840.113556.1.4.417", deletedControl.getID());
    assertTrue(deletedControl.isCritical());
  }

  @Test
  public void testSearchReturnsOneEmptyGroup() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String userDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(filter, "cn", userDn, "users")
               .addSearchResult(filter, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"));
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, true,
        new String[] { "cn", "members", "objectGUID;binary" });
    assertEquals(1, resultSet.size());
    for (AdEntity ae : resultSet) {
      assertEquals("name under", ae.getCommonName());
    }
  }

  @Test
  public void testSearchReturnsOneNonemptyGroup() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String userDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("dn_for_user_1", "dn_for_user_2");
    ldapContext.addSearchResult(filter, "cn", userDn, "users")
               .addSearchResult(filter, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"))
               .addSearchResult(filter, "member", userDn, members);
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, false,
        new String[] { "cn", "member", "objectGUID;binary" });
    assertEquals(1, resultSet.size());
    for (AdEntity ae : resultSet) {
      assertEquals(new HashSet<String>(members), ae.getMembers());
    }
  }

  @Test
  public void testSearchReturnsMembersinTwoRanges() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String filter2 = "(sAMAccountName=sam)";
    final String userDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("dn_for_user_0", "dn_for_user_1");
    List<String> moreMembers = Arrays.asList("dn_for_user_2", "dn_for_user_3");
    ldapContext.addSearchResult(filter, "cn", userDn, "users")
               .addSearchResult(filter, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"))
               .addSearchResult(filter, "sAMAccountName", userDn, "sam")
               .addSearchResult(filter, "member;Range=0-1", userDn, members);
    ldapContext.addSearchResult(filter2, "cn", userDn, "users")
               .addSearchResult(filter2, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"))
               .addSearchResult(filter2, "sAMAccountName", userDn, "sam2")
               .addSearchResult(filter2, "member;Range=2-3*", userDn,
                    moreMembers);
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, false,
        // need the ranged members for MockLdapContext, not for "real" AD.
        new String[] { "cn", "member", "member;Range=0-1", "member;Range=2-3",
                       "objectGUID;binary", "sAMAccountName" });
    assertEquals(1, resultSet.size());
    HashSet<String> expectedMembers = new HashSet<String>(members);
    expectedMembers.addAll(moreMembers);
    for (AdEntity ae : resultSet) {
      assertEquals(expectedMembers, ae.getMembers());
    }
  }

  @Test
  public void testSearchReturnsMembersinThreeRanges() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    addStandardKeysAndResults(ldapContext);
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String filter2 = "(sAMAccountName=sam)";
    final String userDn = "DN_for_default_naming_context";
    List<String> members = Arrays.asList("dn_for_user_0", "dn_for_user_1");
    List<String> moreMembers = Arrays.asList("dn_for_user_2", "dn_for_user_3");
    List<String> evenMore = Arrays.asList("dn_for_user_4");
    ldapContext.addSearchResult(filter, "cn", userDn, "users")
               .addSearchResult(filter, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"))
               .addSearchResult(filter, "sAMAccountName", userDn, "sam")
               .addSearchResult(filter, "member;Range=0-1", userDn, members);
    ldapContext.addSearchResult(filter2, "cn", userDn, "users")
               .addSearchResult(filter2, "objectGUID;binary", userDn,
                   hexStringToByteArray("000102030405060708090a0b0c"))
               .addSearchResult(filter2, "sAMAccountName", userDn, "sam2")
               .addSearchResult(filter2, "member;Range=2-3", userDn,
                    moreMembers)
               .addSearchResult(filter2, "member;Range=4-5*", userDn,
                    evenMore);
    AdServer adServer = new AdServer("localhost", ldapContext);
    adServer.initialize();
    Set<AdEntity> resultSet = adServer.search(filter, false,
        // need the ranged members for MockLdapContext, not for "real" AD.
        new String[] { "cn", "member", "member;Range=0-1", "member;Range=2-3",
                       "member;Range=4-5*", "objectGUID;binary",
                       "sAMAccountName" });
    assertEquals(1, resultSet.size());
    HashSet<String> expectedMembers = new HashSet<String>(members);
    expectedMembers.addAll(moreMembers);
    expectedMembers.addAll(evenMore);
    for (AdEntity ae : resultSet) {
      assertEquals(expectedMembers, ae.getMembers());
    }
  }

  /**
    * Generate a common LdapContext used for various tests above
    */
  private void addStandardKeysAndResults(MockLdapContext ldapContext) {
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
                 "GSA-CONNECTORS")
               .addSearchResult("(ncName=DN_for_default_naming_context)",
                 "dnsRoot",
                 "naming_context",
                 "gsa-connectors.com");
  }

  public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                           + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
  }
}
