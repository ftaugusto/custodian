# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
ResourceMap = {
    # IAM resources
    "ibm.iam-user":             "c7n_ibmcloud.resources.iam.IAMUser",
    "ibm.iam-service-id":       "c7n_ibmcloud.resources.iam.IAMServiceID",
    "ibm.iam-api-key":          "c7n_ibmcloud.resources.iam.IAMApiKey",
    "ibm.iam-access-group":     "c7n_ibmcloud.resources.iam.IAMAccessGroup",
    "ibm.iam-custom-role":      "c7n_ibmcloud.resources.iam.IAMCustomRole",
    "ibm.iam-policy":           "c7n_ibmcloud.resources.iam.IAMPolicy",
    "ibm.iam-trusted-profile":  "c7n_ibmcloud.resources.iam.IAMTrustedProfile",
    # VPC resources
    "ibm.vpc-instance":           "c7n_ibmcloud.resources.vpc.VPCInstance",
    "ibm.vpc-network":            "c7n_ibmcloud.resources.vpc.VPCNetwork",
    "ibm.vpc-subnet":             "c7n_ibmcloud.resources.vpc.VPCSubnet",
    "ibm.vpc-security-group":     "c7n_ibmcloud.resources.vpc.VPCSecurityGroup",
    "ibm.vpc-floating-ip":        "c7n_ibmcloud.resources.vpc.VPCFloatingIP",
    "ibm.vpc-volume":             "c7n_ibmcloud.resources.vpc.VPCVolume",
    "ibm.vpc-load-balancer":      "c7n_ibmcloud.resources.vpc.VPCLoadBalancer",
    "ibm.vpc-public-gateway":     "c7n_ibmcloud.resources.vpc.VPCPublicGateway",
    "ibm.vpc-network-acl":        "c7n_ibmcloud.resources.vpc.VPCNetworkACL",
    "ibm.vpc-vpn-gateway":        "c7n_ibmcloud.resources.vpc.VPCVPNGateway",
    "ibm.vpc-bare-metal":         "c7n_ibmcloud.resources.vpc.VPCBareMetal",
    "ibm.vpc-dedicated-host":     "c7n_ibmcloud.resources.vpc.VPCDedicatedHost",
    "ibm.vpc-file-share":         "c7n_ibmcloud.resources.vpc.VPCFileShare",
    "ibm.vpc-ssh-key":            "c7n_ibmcloud.resources.vpc.VPCSSHKey",
    "ibm.vpc-instance-group":     "c7n_ibmcloud.resources.vpc.VPCInstanceGroup",
    "ibm.vpc-instance-template":  "c7n_ibmcloud.resources.vpc.VPCInstanceTemplate",
    "ibm.vpc-snapshot":           "c7n_ibmcloud.resources.vpc.VPCSnapshot",
    "ibm.vpc-backup-policy":      "c7n_ibmcloud.resources.vpc.VPCBackupPolicy",
    "ibm.vpc-transit-gateway":    "c7n_ibmcloud.resources.vpc.VPCTransitGateway",
    # COS resources
    "ibm.cos-bucket":           "c7n_ibmcloud.resources.cos.COSBucket",
    # KMS resources
    "ibm.kms-key":              "c7n_ibmcloud.resources.kms.KMSKey",
    "ibm.kms-key-ring":         "c7n_ibmcloud.resources.kms.KMSKeyRing",
    # Kubernetes / OpenShift resources
    "ibm.iks-cluster":          "c7n_ibmcloud.resources.kubernetes.IKSCluster",
    "ibm.roks-cluster":         "c7n_ibmcloud.resources.kubernetes.ROKSCluster",
    "ibm.iks-worker-pool":      "c7n_ibmcloud.resources.kubernetes.IKSWorkerPool",
    # PowerVS resources
    "ibm.powervs-instance":     "c7n_ibmcloud.resources.powervs.PowerVSInstance",
    "ibm.powervs-volume":       "c7n_ibmcloud.resources.powervs.PowerVSVolume",
    "ibm.powervs-network":      "c7n_ibmcloud.resources.powervs.PowerVSNetwork",
    "ibm.powervs-image":        "c7n_ibmcloud.resources.powervs.PowerVSImage",
    "ibm.powervs-ssh-key":      "c7n_ibmcloud.resources.powervs.PowerVSSSHKey",
    # DBaaS resources
    "ibm.dbaas-postgresql":     "c7n_ibmcloud.resources.dbaas.IcdPostgreSQL",
    "ibm.dbaas-mysql":          "c7n_ibmcloud.resources.dbaas.IcdMySQL",
    "ibm.dbaas-mongodb":        "c7n_ibmcloud.resources.dbaas.IcdMongoDB",
    "ibm.dbaas-redis":          "c7n_ibmcloud.resources.dbaas.IcdRedis",
    "ibm.dbaas-elasticsearch":  "c7n_ibmcloud.resources.dbaas.IcdElasticsearch",
    "ibm.dbaas-rabbitmq":       "c7n_ibmcloud.resources.dbaas.IcdRabbitMQ",
}
