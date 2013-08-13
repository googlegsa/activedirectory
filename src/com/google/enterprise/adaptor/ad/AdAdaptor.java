// Copyright 2011 Google Inc. All Rights Reserved.
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
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import java.io.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.logging.Logger;

/** Adaptor for Active Directory. */
public class AdAdaptor extends AbstractAdaptor {
  private static final Logger log
      = Logger.getLogger(AdAdaptor.class.getName());
  private Charset encoding = Charset.forName("UTF-8");
  private static final boolean CASE_SENSITIVE = false;

  /** Gives list of document ids that you'd like on the GSA. */
  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException {
    pusher.pushGroupDefinitions(null, CASE_SENSITIVE);
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
}
