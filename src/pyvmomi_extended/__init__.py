# Copyright 2025 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""Extension of pyVmomi

This module contains functionality to make additional objects known to pyVmomi.
It also contains some object definitions we encountered, that are not known to
pyVmomi.
"""

import pyVmomi
from pyVmomi import VmomiSupport
from pyVmomi.VmomiSupport import F_OPTIONAL, AddVersion, CreateDataType, CreateManagedType


def _register_new_module(name) -> None:
    """Register a module to pyVmomi

    This is copied and adapted from pyVmomi/__init__.py
    """
    VmomiSupport._topLevelNames.add(name)
    upper_case_name = VmomiSupport.Capitalize(name)
    obj = VmomiSupport.LazyModule(name)
    setattr(pyVmomi, name, obj)
    if pyVmomi._allowCapitalizedNames:
        setattr(pyVmomi, upper_case_name, obj)
    if not hasattr(VmomiSupport.types, name):
        setattr(VmomiSupport.types, name, obj)
        if pyVmomi._allowCapitalizedNames:
            setattr(VmomiSupport.types, upper_case_name, obj)


SSO_VERSION = "sso.version.version1"


def _register_sso() -> None:
    """Register the `sso` module to pyVmomi"""
    version = SSO_VERSION

    AddVersion(version, "sso", "version2", 0, "sso")

    CreateDataType("sso.SsoFaultInvalidPrincipalFault", "SsoFaultInvalidPrincipalFault",
                   "vmodl.MethodFault", version,
                   [("principal", "string", version, 0)])

    CreateDataType("sso.PrincipalId", "SsoPrincipalId",
                   "vmodl.DynamicData", version,
                   [("name", "string", version, 0),
                    ("domain", "string", version, 0)])

    CreateDataType("sso.AdminUser", "AdminUser",
                   "vmodl.DynamicData", version,
                   [("id", "sso.PrincipalId", version, 0),
                    ("alias", "sso.PrincipalId", version, F_OPTIONAL),
                    ("kind", "string", version, 0),
                    ("description", "string", version, F_OPTIONAL)])

    CreateDataType("sso.AdminSolutionDetails", "AdminSolutionDetails",
                   "vmodl.DynamicData", version,
                   [("description", "string", version, F_OPTIONAL),
                    ("certificate", "string", version, 0)])
    CreateDataType("sso.AdminSolutionUser", "AdminSolutionUser",
                   "vmodl.DynamicData", version,
                   [("id", "sso.PrincipalId", version, 0),
                    ("alias", "sso.PrincipalId", version, F_OPTIONAL),
                    ("details", "sso.AdminSolutionDetails", version, 0),
                    ("disabled", "boolean", version, 0)])

    CreateDataType("sso.AdminPersonDetails", "AdminPersonDetails",
                   "vmodl.DynamicData", version,
                   [("description", "string", version, F_OPTIONAL),
                    ("emailAddress", "string", version, F_OPTIONAL),
                    ("firstName", "string", version, F_OPTIONAL),
                    ("lastName", "string", version, F_OPTIONAL)])
    CreateDataType("sso.AdminPersonUser", "AdminPersonUser",
                   "vmodl.DynamicData", version,
                   [("id", "sso.PrincipalId", version, 0),
                    ("alias", "sso.PrincipalId", version, F_OPTIONAL),
                    ("details", "sso.AdminPersonDetails", version, 0),
                    ("disabled", "boolean", version, 0),
                    ("locked", "boolean", version, 0)])

    CreateDataType("sso.AdminGroupDetails", "AdminGroupDetails",
                   "vmodl.DynamicData", version,
                   [("description", "string", version, F_OPTIONAL)])
    CreateDataType("sso.AdminGroup", "AdminGroup",
                   "vmodl.DynamicData", version,
                   [("id", "sso.PrincipalId", version, 0),
                    ("alias", "sso.PrincipalId", version, F_OPTIONAL),
                    ("details", "sso.AdminGroupDetails", version, 0)])

    CreateDataType("sso.AdminPrincipalDiscoveryServiceSearchCriteria",
                   "SsoAdminPrincipalDiscoveryServiceSearchCriteria",
                   "vmodl.DynamicData", version,
                   [("searchString", "string", version, 0),
                    ("domain", "string", version, 0)])

    CreateManagedType("sso.SsoAdminPrincipalDiscoveryService", "SsoAdminPrincipalDiscoveryService",
                      "vmodl.ManagedObject", version,
                      None,
                      [("findUser", "FindUser", version,
                        (("userId", "sso.PrincipalId", version, 0, None), ),
                        (0, "sso.AdminUser", "sso.AdminUser"),
                        "System.Anonymous", ["sso.SsoFaultInvalidPrincipalFault"]),
                       ("findUsers", "FindUsers", version,
                        (("criteria", "sso.AdminPrincipalDiscoveryServiceSearchCriteria", version, 0, None),
                         ("limit", "int", version, F_OPTIONAL, None)),
                        (F_OPTIONAL, "sso.AdminUser[]", "sso.AdminUser[]"),
                        "System.Anonymous", None),
                       ("findSolutionUsers", "FindSolutionUsers", version,
                        (("searchString", "string", version, 0, None),
                         ("limit", "int", version, F_OPTIONAL, None)),
                        (F_OPTIONAL, "sso.AdminSolutionUser[]", "sso.AdminSolutionUser[]"),
                        "System.Anonymous", None),
                       ("findPersonUsers", "FindPersonUsers", version,
                        (("criteria", "sso.AdminPrincipalDiscoveryServiceSearchCriteria", version, 0, None),
                         ("limit", "int", version, F_OPTIONAL, None)),
                        (F_OPTIONAL, "sso.AdminPersonUser[]", "sso.AdminPersonUser[]"),
                        "System.Anonymous", None),
                       ("findGroups", "FindGroups", version,
                        (("criteria", "sso.AdminPrincipalDiscoveryServiceSearchCriteria", version, 0, None),
                         ("limit", "int", version, F_OPTIONAL, None)),
                        (F_OPTIONAL, "sso.AdminGroup[]", "sso.AdminGroup[]"),
                        "System.Anonymous", None),
                       ("findUsersInGroup", "FindUsersInGroup", version,
                        (("groupId", "sso.PrincipalId", version, 0, None),
                         ("searchString", "string", version, 0, None),
                         ("limit", "int", version, 0, None)),
                        (F_OPTIONAL, "sso.AdminUser[]", "sso.AdminUser[]"),
                        "System.Anonymous", None),
                       ("findNestedParentGroups", "FindNestedParentGroups", version,
                        (("userId", "sso.PrincipalId", version, 0, None), ),
                        (F_OPTIONAL, "sso.AdminGroup[]", "sso.AdminGroup[]"),
                        "System.Anonymous", None),
                       ("findParentGroups", "FindParentGroups", version,
                        (("userId", "sso.PrincipalId", version, 0, None),
                         ("groupList", "sso.PrincipalId[]", version, F_OPTIONAL, None)),
                        (F_OPTIONAL, "sso.PrincipalId[]", "sso.PrincipalId[]"),
                        "System.Anonymous", None),

                       # there's a generic `Find` function that can find
                       # PersonUser, SolutionUser and Group objects
                       # DisableUserAccountRequestType
                       # EnableUserAccountRequestType
                       # HasAdministratorRoleRequestType
                       # IsMemberOfGroup
                       ])


    CreateDataType("sso.CreateLocalPersonUserResponse", "CreateLocalPersonUserResponse",
                   "vmodl.DynamicData", version,
                   [("name", "string", version, 0),
                    ("domain", "string", version, 0)])

    CreateManagedType("sso.SsoAdminPrincipalManagementService", "SsoAdminPrincipalManagementService",
                      "vmodl.ManagedObject", version,
                      None,
                      [("getDaysRemainingUntilPasswordExpiration", "GetDaysRemainingUntilPasswordExpiration", version,
                        (("userId", "sso.PrincipalId", version, 0, None), ),
                        (0, "int", "int"),
                        "System.Anonymous", None),
                       ("createLocalPersonUser", "CreateLocalPersonUser", version,
                        (("userName", "string", version, 0, None),
                         ("userDetails", "sso.AdminPersonDetails", version, 0, None),
                         ("password", "string", version, 0, None)),
                        (0, "sso.CreateLocalPersonUserResponse", "sso.CreateLocalPersonUserResponse"),
                        "System.Anonymous", None),
                       ("deleteLocalPrincipal", "DeleteLocalPrincipal", version,
                        (("principalName", "string", version, 0, None), ),
                        (0, "vmodl.DynamicData", "vmodl.DynamicData"),
                        "System.Anonymous", None),

                       ("addUsersToLocalGroup", "AddUsersToLocalGroup", version,
                        (("userIds", "sso.PrincipalId[]", version, 0, None),
                         ("groupName", "string", version, 0, None)),
                        (0, "boolean[]", "boolean[]"),
                        "System.Anonymous", None),
                       ("removePrincipalsFromLocalGroup", "RemovePrincipalsFromLocalGroup", version,
                        (("principalIds", "sso.PrincipalId[]", version, 0, None),
                         ("groupName", "string", version, 0, None)),
                        (0, "boolean[]", "boolean[]"),
                        "System.Anonymous", None),

                       ("resetLocalPersonUserPassword", "ResetLocalPersonUserPassword", version,
                        (("userName", "string", version, 0, None),
                         ("newPassword", "string", version, 0, None)),
                        (0, "vmodl.DynamicData", "vmodl.DynamicData"),
                        "System.Anonymous", None),
                      ])

    CreateDataType("sso.AdminPasswordFormatLengthRestriction", "AdminPasswordFormatLengthRestriction",
                   "vmodl.DynamicData", version,
                   [("minLength", "int", version, 0),
                    ("maxLength", "int", version, 0)])
    CreateDataType("sso.AdminPasswordFormatAlphabeticRestriction", "AdminPasswordFormatAlphabeticRestriction",
                   "vmodl.DynamicData", version,
                   [("minAlphabeticCount", "int", version, 0),
                    ("minUppercaseCount", "int", version, 0),
                    ("minLowercaseCount", "int", version, 0)])
    CreateDataType("sso.AdminPasswordFormat", "AdminPasswordFormat",
                   "vmodl.DynamicData", version,
                   [("lengthRestriction", "sso.AdminPasswordFormatLengthRestriction", version, 0),
                    ("alphabeticRestriction", "sso.AdminPasswordFormatAlphabeticRestriction", version, 0),
                    ("minNumericCount", "int", version, 0),
                    ("minSpecialCharCount", "int", version, 0),
                    ("maxIdenticalAdjacentCharacters", "int", version, 0)])
    CreateDataType("sso.AdminPasswordPolicy", "AdminPasswordPolicy",
                   "vmodl.DynamicData", version,
                   [("description", "string", version, 0),
                    ("prohibitedPreviousPasswordsCount", "int", version, 0),
                    ("passwordFormat", "sso.AdminPasswordFormat", version, 0),
                    ("passwordLifetimeDays", "int", version, F_OPTIONAL)])

    CreateManagedType("sso.SsoAdminPasswordPolicyService", "SsoAdminPasswordPolicyService",
                      "vmodl.ManagedObject", version,
                      None,
                      [("getLocalPasswordPolicy", "GetLocalPasswordPolicy", version,
                        [],
                        (0, "sso.AdminPasswordPolicy", "sso.AdminPasswordPolicy"),
                        "System.Anonymous", None),
                      ])

    CreateManagedType("sso.SsoSessionManager", "SsoSessionManager",
                      "vmodl.ManagedObject", version,
                      None,
                      [("login", "Login", version,
                        [],
                        (0, "vmodl.DynamicData", "vmodl.DynamicData"),
                        "System.Anonymous", None)])

    CreateDataType("sso.SsoAdminAboutInfo", "AboutInfo",
                   "vmodl.DynamicData", version,
                   [("version", "string", version, 0),
                    ("build", "string", version, 0),
                    ("apiRevision", "string", version, 0),
                    ("clusterId", "string", version, 0),
                    ("deploymentId", "string", version, 0),
                   ])

    # TODO(jkulik): These are just stubs to make AdminServiceContent work
    CreateManagedType("sso.SsoAdminConfigurationManagementService", "SsoAdminConfigurationManagementService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateManagedType("sso.SsoAdminSmtpManagementService", "SsoAdminSmtpManagementService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateManagedType("sso.SsoAdminRoleManagementService", "SsoAdminRoleManagementService",
                      "vmodl.ManagedObject", version,
                      None,
                      [("hasAdministratorRole", "HasAdministratorRole", version,
                        (("userId", "sso.PrincipalId", version, 0, None), ),
                        (0, "boolean", "boolean"),
                        "System.Anonymous", None),
                       ("hasRegularUserRole", "HasRegularUserRole", version,
                        (("userId", "sso.PrincipalId", version, 0, None), ),
                        (0, "boolean", "boolean"),
                        "System.Anonymous", None),
                       ("setRole", "SetRole", version,
                        (("userId", "sso.PrincipalId", version, 0, None),
                         ("role", "string", version, 0, None)),
                        (0, "boolean", "boolean"),
                        "System.Anonymous", None),
                      ])
    CreateManagedType("sso.SsoAdminLockoutPolicyService", "SsoAdminLockoutPolicyService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateManagedType("sso.SsoAdminDomainManagementService", "SsoAdminDomainManagementService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateManagedType("sso.SsoAdminIdentitySourceManagementService", "SsoAdminIdentitySourceManagementService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateManagedType("sso.SsoAdminSystemManagementService", "SsoAdminSystemManagementService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateManagedType("sso.SsoAdminDeploymentInformationService", "SsoAdminDeploymentInformationService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateManagedType("sso.SsoAdminReplicationService", "SsoAdminReplicationService",
                      "vmodl.ManagedObject", version,
                      None,
                      [])
    CreateDataType("sso.AdminServiceContent", "AdminServiceContent",
                   "vmodl.DynamicData", version,
                   [("sessionManager", "sso.SsoSessionManager", version, 0),
                    ("configurationManagementService", "sso.SsoAdminConfigurationManagementService", version, 0),
                    ("smtpManagementService", "sso.SsoAdminSmtpManagementService", version, 0),
                    ("principalDiscoveryService", "sso.SsoAdminPrincipalDiscoveryService", version, 0),
                    ("principalManagementService", "sso.SsoAdminPrincipalManagementService", version, 0),
                    ("roleManagementService", "sso.SsoAdminRoleManagementService", version, 0),
                    ("passwordPolicyService", "sso.SsoAdminPasswordPolicyService", version, 0),
                    ("lockoutPolicyService", "sso.SsoAdminLockoutPolicyService", version, 0),
                    ("domainManagementService", "sso.SsoAdminDomainManagementService", version, 0),
                    ("identitySourceManagementService", "sso.SsoAdminIdentitySourceManagementService", version, 0),
                    ("systemManagementService", "sso.SsoAdminSystemManagementService", version, 0),
                    ("deploymentInformationService", "sso.SsoAdminDeploymentInformationService", version, 0),
                    ("replicationService", "sso.SsoAdminReplicationService", version, 0),
                    ("aboutInfo", "sso.SsoAdminAboutInfo", version, 0),
                   ])

    CreateManagedType("sso.SsoAdminServiceInstance", "SsoAdminServiceInstance",
                      "vmodl.ManagedObject", version,
                      None,
                      [("SsoAdminServiceInstance", "SsoAdminServiceInstance", version,
                        [],
                        (0, "sso.AdminServiceContent", "sso.AdminServiceContent"),
                        "System.Anonymous", None)])


    _register_new_module('sso')


def _register_results() -> None:
    """Register Task results unknown to pyVmomi"""
    CreateDataType("vim.vm.device.VirtualQAT", "VirtualQAT",
                   "vim.vm.device.VirtualDevice", "vim.version.v7_0", None)
    CreateDataType("vim.vm.device.VirtualQAT.DeviceBackingInfo", "VirtualQATDeviceBackingInfo",
                   "vim.vm.device.VirtualDevice.DeviceBackingInfo", "vim.version.v7_0", None)
    CreateDataType("vim.vm.device.VirtualQATOption", "VirtualQATOption",
                   "vim.vm.device.VirtualDeviceOption", "vim.version.v7_0", None)
    CreateDataType("vim.vm.device.VirtualQATOption.DeviceBackingOption", "VirtualQATDeviceBackingOption",
                   "vim.vm.device.VirtualDeviceOption.DeviceBackingOption", "vim.version.v7_0", None)
    CreateDataType('vim.HostVMotionManagerVMotionResult', 'HostVMotionManagerVMotionResult',
                   'vim.host.VMotionManager.DstInstantCloneResult', 'vim.version.v7_0',
                   [['vmDowntime', 'int', 'vim.version.v7_0', F_OPTIONAL],
                    ['vmStunTime', 'int', 'vim.version.v7_0', F_OPTIONAL],
                    ['vmPagesSrcTime', 'int', 'vim.version.v7_0', F_OPTIONAL],
                    ['vmNumRemotePageFaults', 'int', 'vim.version.v7_0', F_OPTIONAL],
                    ['dstMigrationTime', 'int', 'vim.version.v7_0', F_OPTIONAL],
                    ['vmotionRTT', 'int', 'vim.version.v7_0', F_OPTIONAL],
                    ['isVmotionAtHighRTT', 'int', 'vim.version.v7_0', F_OPTIONAL],
                   ])


def _register_pbm_result() -> None:
    """Register sometimes occurring output of PbmQueryAssociatedProfiles"""
    CreateDataType("pbm.profile.QueryProfileResultInternal", "PbmProfileQueryProfileResultInternal",
                   "pbm.profile.QueryProfileResult", "pbm.version.version1",
                   [('defaultPolicy', 'string', 'pbm.version.version1', 0),  # guessed
                    ('autoRg', 'bool', 'pbm.version.version1', 0)])          # guessed


def extend_pyvmomi():
    """Call all the extension functions to extend pyVmomi"""
    _register_sso()
    _register_results()
    _register_pbm_result()
