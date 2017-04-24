/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.has.webserver;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.http.HttpConfig;

/** 
 * This class contains constants for configuration keys and default values
 * used in hdfs.
 */
@InterfaceAudience.Private
public class HASConfigKeys extends CommonConfigurationKeys {

  public static final String  HAS_HTTP_ADDRESS_KEY = "has.http-address";
  public static final int     HAS_PORT_DEFAULT = 9870;
  public static final String  HAS_HTTPS_ADDRESS_KEY = "has.https-address";
  public static final String  HAS_HTTPS_BIND_HOST_KEY = "has.https-bind-host";
  public static final String  HAS_HTTP_POLICY_KEY = "has.http.policy";
  public static final String  HAS_HTTP_POLICY_DEFAULT =  HttpConfig.Policy.HTTP_ONLY.name();

  public static final String  HAS_HTTPS_PORT_KEY = "has.https.port";
  public static final int     HAS_HTTPS_DEFAULT_PORT = 9865;
  public static final String  HAS_HTTPS_ADDRESS_DEFAULT = "0.0.0.0:" + HAS_HTTPS_DEFAULT_PORT;

  public static final String  HAS_SERVER_HTTPS_KEYSTORE_RESOURCE_KEY = "has.https.server.keystore.resource";
  public static final String  HAS_SERVER_HTTPS_KEYSTORE_RESOURCE_DEFAULT = "ssl-server.xml";
  public static final String  HAS_SERVER_HTTPS_KEYPASSWORD_KEY = "ssl.server.keystore.keypassword";
  public static final String  HAS_SERVER_HTTPS_KEYSTORE_PASSWORD_KEY = "ssl.server.keystore.password";
  public static final String  HAS_SERVER_HTTPS_KEYSTORE_LOCATION_KEY = "ssl.server.keystore.location";
  public static final String  HAS_SERVER_HTTPS_TRUSTSTORE_LOCATION_KEY = "ssl.server.truststore.location";
  public static final String  HAS_SERVER_HTTPS_TRUSTSTORE_PASSWORD_KEY = "ssl.server.truststore.password";
  public static final String  HAS_CLIENT_HTTPS_NEED_AUTH_KEY = "has.client.https.need-auth";
  public static final boolean HAS_CLIENT_HTTPS_NEED_AUTH_DEFAULT = false;
}
