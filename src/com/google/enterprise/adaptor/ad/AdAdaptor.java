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

import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.UserPrincipal;

import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InterruptedNamingException;

/** Adaptor for Active Directory. */
public class AdAdaptor extends AbstractAdaptor {
  private static final Logger log
      = Logger.getLogger(AdAdaptor.class.getName());
  // private static final Charset ENCODING = Charset.forName("UTF-8");
  private static final boolean CASE_SENSITIVITY = false;

  private String namespace;
  private String domain;
  private List<AdServer> servers = new ArrayList<AdServer>();

  @Override
  public void initConfig(Config config) {
    config.addKey("ad.servers", null);
    config.addKey("ad.namespace", "Default");
    // TODO: pull domain from AD
    config.addKey("ad.domain", null);
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    namespace = context.getConfig().getValue("ad.namespace");
    log.config("common namespace: " + namespace);
    domain = context.getConfig().getValue("ad.domain");
    log.config("common domain: " + domain);
    List<Map<String, String>> serverConfigs
        = context.getConfig().getListOfConfigs("ad.servers");
    for (Map<String, String> singleServerConfig : serverConfigs) {
      String host = singleServerConfig.get("host");
      int port = Integer.parseInt(singleServerConfig.get("port"));
      Method method = null;
      if ("ssl".equals(singleServerConfig.get("method").toLowerCase())) {
        method = Method.SSL;
      } else {
        method = Method.STANDARD;
      }
      String principal = singleServerConfig.get("user");
      String passwd = singleServerConfig.get("password");
      AdServer adServer = new AdServer(method, host, port, principal, passwd);
      servers.add(adServer);
      Map<String, String> dup = new TreeMap<String, String>(singleServerConfig);
      dup.put("password", "XXXXXX");
      log.config("AD server spec: " + dup);
    }
  }

  /** This adaptor does not serve documents. */
  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    resp.respondNotFound();
  }

  /** Call default main for adaptors. */
  public static void main(String[] args) {
    AbstractAdaptor.main(new AdAdaptor(), args);
  }

  /** Pushes all groups from all AdServers. */
  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException {
    // TODO: implement well known groups
    // TODO: implement built in groups
    for (AdServer server : servers) {
      server.initialize();
      try {
        GroupCatalog catalog = new GroupCatalog();
        catalog.readFrom(server);
        pusher.pushGroupDefinitions(catalog.makeDefs(), CASE_SENSITIVITY);
      } catch (InterruptedNamingException ine) {
        String host = server.getHostName();
        log.log(Level.WARNING, "skipping " + host, ine);
      }
    } 
  }

  // Space for all group info, organized in different ways
  private class GroupCatalog {
    Set<AdEntity> entities = new HashSet<AdEntity>();
    Map<AdEntity, Set<String>> members = new HashMap<AdEntity, Set<String>>();

    Map<String, AdEntity> bySid = new HashMap<String, AdEntity>();
    Map<String, AdEntity> byDn = new HashMap<String, AdEntity>();
   
    void readFrom(AdServer server) throws InterruptedNamingException {
      entities = server.search(AdConstants.LDAP_QUERY, /*deleted=*/ false,
          new String[] {
              AdConstants.ATTR_USNCHANGED,
              AdConstants.ATTR_SAMACCOUNTNAME,
              AdConstants.ATTR_OBJECTSID,
              AdConstants.ATTR_OBJECTGUID,
              AdConstants.ATTR_UPN,
              AdConstants.ATTR_PRIMARYGROUPID,
              AdConstants.ATTR_MEMBER}
      );
      int n = entities.size();
      log.log(Level.FINE, "received " + n + " entities from server");
      for (AdEntity e : entities) {
        bySid.put(e.getSid(), e);
        byDn.put(e.getDn(), e);
      }
      resolvePrimaryGroups();
      resolveForeignSecurityPrincipals();
    }

    private void resolvePrimaryGroups() {
      for (AdEntity e : entities) {
        if (e.isGroup()) {
          continue;
        }
        AdEntity user = e;
        AdEntity primaryGroup = bySid.get(user.getPrimaryGroupSid());
        if (!members.containsKey(primaryGroup)) {
          members.put(primaryGroup, new TreeSet<String>());
        }
        members.get(primaryGroup).add(user.getDn());
      }
    }

    private void resolveForeignSecurityPrincipals() {
      for (AdEntity entity : entities) {
        if (!entity.isGroup()) {
          continue;
        }
        if (!members.containsKey(entity)) {
          continue;
        }
        Set<String> resolvedMembers = new HashSet<String>();
        for (String member : members.get(entity)) {
          String sid = AdEntity.parseForeignSecurityPrincipal(member);
          if (null == sid) {
            resolvedMembers.add(member);
          } else {
            AdEntity resolved = bySid.get(sid);
            if (null == resolved) {
              log.info("unable to resolve foreign principal ["
                  + member + "]; member of [" + entity.getDn());
            } else {
              resolvedMembers.add(resolved.getDn());
            }
          }
        }
        members.put(entity, resolvedMembers);
      }
    }

    private Map<GroupPrincipal, List<Principal>> makeDefs() {
      Map<GroupPrincipal, List<Principal>> groups
          = new HashMap<GroupPrincipal, List<Principal>>();
      for (AdEntity entity : entities) {
        if (!entity.isGroup()) {
          continue;
        }
        // TODO: get domain from entity
        GroupPrincipal group = new GroupPrincipal(
            entity.getSAMAccountName() + "@" + domain, namespace);
        List<Principal> def = new ArrayList<Principal>();
        if (members.containsKey(entity)) {
          for (String memberDn : members.get(entity)) {
            AdEntity member = byDn.get(memberDn);
            if (member == null) {
              log.info("Unknown member [" + memberDn + "] of group ["
                  + entity.getDn());
              continue;
            }
            Principal p;
            if (member.isGroup()) {
              // TODO: get domain from entity
              p = new GroupPrincipal(
                  member.getSAMAccountName() + "@" + domain, namespace);
            } else {
              // TODO: get domain from entity
              p = new UserPrincipal(
                  member.getSAMAccountName() + "@" + domain, namespace);
            }
            def.add(p);
          }
        }
        groups.put(group, def);
      }
      if (log.isLoggable(Level.FINE)) {
        log.fine("number of groups defined: " + groups.keySet().size());
      }
      if (log.isLoggable(Level.FINER)) {
        int numGroups = groups.keySet().size();
        int totalMembers = 0;
        for (List<Principal> def : groups.values()) {
          totalMembers += def.size();
        }
        if (0 != numGroups) {
          double mean = ((double) totalMembers) / numGroups;
          log.finer("mean size of defined group: " + mean);
        }
      }
      return groups;
    }
  }
}
