/*
 * Copyright 2019 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.kork.secrets.engines;

import static org.junit.Assert.*;

import com.netflix.spinnaker.kork.secrets.EncryptedSecret;
import java.io.IOException;
import java.io.InputStreamReader;
import org.junit.Test;

public class S3SecretEngineTest {

  @Test
  public void downloadRemoteFile() throws IOException {
    String secretConfig =
        "encrypted:s3!b:spin-secret-test!r:us-east-1!f:secret.yml!R:arn:aws:iam::472623979816:role/devops-hq";
    EncryptedSecret encryptedSecret = new EncryptedSecret(secretConfig);
    S3SecretEngine engine = new S3SecretEngine();
    InputStreamReader isr = new InputStreamReader(engine.downloadRemoteFile(encryptedSecret));
  }
}
