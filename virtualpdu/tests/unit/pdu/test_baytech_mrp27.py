# Copyright 2016 Internap
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from virtualpdu.pdu import baytech_mrp27
from virtualpdu.tests import base
from virtualpdu.tests.unit.pdu.base_pdu_test_cases import BasePDUTests


class TestBaytechMRP27PDU(base.TestCase, BasePDUTests):
    pdu_class = baytech_mrp27.BaytechMRP27PDU
    outlet_control_oid = \
        baytech_mrp27.sBTA_modules_RPC_outlet_state \
        + (1, baytech_mrp27.BaytechMRP27PDU.outlet_index_start,)