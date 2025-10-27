/*
 * Copyright 2013-2022 Step Function I/O, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Step Function I/O
 * LLC (https://stepfunc.io) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Step Function I/O LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>

#include <exe4cpp/MockExecutor.h>

#include <dnp3mocks/MockLowerLayer.h>
#include <dnp3mocks/MockMasterApplication.h>
#include <dnp3mocks/MockSOEHandler.h>

#include <master/MasterContext.h>
#include <master/MasterSchedulerBackend.h>

#include "NullLogHandler.h"

class MasterTestObject {
public:
  MasterTestObject(const opendnp3::MasterParams &params) : addresses(), logger(), exe(std::make_shared<exe4cpp::MockExecutor>()), meas(std::make_shared<MockSOEHandler>()), lower(std::make_shared<MockLowerLayer>()), application(std::make_shared<MockMasterApplication>()), scheduler(std::make_shared<opendnp3::MasterSchedulerBackend>(exe)), context(opendnp3::MContext::Create(addresses, logger.get_logger(), exe, lower, meas, application, this->scheduler, params)) { lower->SetUpperLayer(*context); }

  ~MasterTestObject() { this->scheduler->Shutdown(); }

  size_t SendToMaster(const ser4cpp::rseq_t &buffer) {
    context->OnReceive(opendnp3::Message(this->addresses.Reverse(), buffer));
    return exe->run_many();
  }

  size_t LowerLayerUp() {
    context->OnLowerLayerUp();
    return exe->run_many();
  }

private:
  const opendnp3::Addresses addresses;

  const NullLogger logger;
  const std::shared_ptr<exe4cpp::MockExecutor> exe;
  const std::shared_ptr<MockSOEHandler> meas;
  const std::shared_ptr<MockLowerLayer> lower;
  const std::shared_ptr<MockMasterApplication> application;
  const std::shared_ptr<opendnp3::IMasterScheduler> scheduler;
  const std::shared_ptr<opendnp3::MContext> context;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  ser4cpp::rseq_t buffer(Data, Size);

  opendnp3::MasterParams config;
  MasterTestObject t(config);
  t.LowerLayerUp();
  t.SendToMaster(buffer);
  return 0;
}
