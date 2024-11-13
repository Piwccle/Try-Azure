@description('Stack name')
param stackName string

@description('''
[selfsigned] Not recommended for production use. If you don't have a FQDN, (DomainName parameter) you can use this option to generate a self-signed certificate.
[owncert] Valid for productions environments. If you have a FQDN, (DomainName parameter)
and an Elastic IP, you can use this option to use your own certificate.
[letsencrypt] Valid for production environments. If you have a FQDN, (DomainName parameter)
and an Elastic IP, you can use this option to generate a Let's Encrypt certificate.
''')
@allowed([
  'selfsigned'
  'owncert'
  'letsencrypt'
])
param certificateType string = 'selfsigned'

@description('Previously created Public IP address for the OpenVidu Deployment. Blank will generate a public IP')
param publicIpAddress string = ''

@description('Name of the PublicIPAddress resource in your azure if you have a resource of publicIPAddress')
param publicIpAddressResourceName string = ''

@description('Domain name for the OpenVidu Deployment. Black will generate default domain')
param domainName string = ''

@description('If certificate type is \'owncert\', this parameter will be used to specify the public certificate')
param ownPublicCertificate string = ''

@description('If certificate type is \'owncert\', this parameter will be used to specify the private certificate')
param ownPrivateCertificate string = ''

@description('If certificate type is \'letsencrypt\', this email will be used for Let\'s Encrypt notifications')
param letsEncryptEmail string = ''

@description('(Optional) Domain name for the TURN server with TLS. Only needed if your users are behind restrictive firewalls')
param turnDomainName string = ''

@description('(Optional) This setting is applicable if the certificate type is set to \'owncert\' and the TurnDomainName is specified.')
param turnOwnPublicCertificate string = ''

@description('(Optional) This setting is applicable if the certificate type is set to \'owncert\' and the TurnDomainName is specified.')
param turnOwnPrivateCertificate string = ''

@description('Location for all the resources')
param location string = resourceGroup().location

// Azure instance config
@description('Specifies the azure vm size for your OpenVidu instance')
@allowed([
  'Standard_B1s'
  'Standard_B1ms'
  'Standard_B2s'
  'Standard_B2ms'
  'Standard_B4ms'
  'Standard_B8ms'
  'Standard_D2_v3'
  'Standard_D4_v3'
  'Standard_D8_v3'
  'Standard_D16_v3'
  'Standard_D32_v3'
  'Standard_D48_v3'
  'Standard_D64_v3'
  'Standard_D2_v4'
  'Standard_D4_v4'
  'Standard_D8_v4'
  'Standard_D16_v4'
  'Standard_D32_v4'
  'Standard_D48_v4'
  'Standard_D64_v4'
  'Standard_D96_v4'
  'Standard_D2_v5'
  'Standard_D4_v5'
  'Standard_D8_v5'
  'Standard_D16_v5'
  'Standard_D32_v5'
  'Standard_D48_v5'
  'Standard_D64_v5'
  'Standard_D96_v5'
  'Standard_F2'
  'Standard_F4'
  'Standard_F8'
  'Standard_F16'
  'Standard_F32'
  'Standard_F64'
  'Standard_F72'
  'Standard_F2s_v2'
  'Standard_F4s_v2'
  'Standard_F8s_v2'
  'Standard_F16s_v2'
  'Standard_F32s_v2'
  'Standard_F64s_v2'
  'Standard_F72s_v2'
  'Standard_E2_v3'
  'Standard_E4_v3'
  'Standard_E8_v3'
  'Standard_E16_v3'
  'Standard_E32_v3'
  'Standard_E48_v3'
  'Standard_E64_v3'
  'Standard_E96_v3'
  'Standard_E2_v4'
  'Standard_E4_v4'
  'Standard_E8_v4'
  'Standard_E16_v4'
  'Standard_E32_v4'
  'Standard_E48_v4'
  'Standard_E64_v4'
  'Standard_E2_v5'
  'Standard_E4_v5'
  'Standard_E8_v5'
  'Standard_E16_v5'
  'Standard_E32_v5'
  'Standard_E48_v5'
  'Standard_E64_v5'
  'Standard_E96_v5'
  'Standard_M64'
  'Standard_M128'
  'Standard_M208ms_v2'
  'Standard_M416ms_v2'
  'Standard_L4s_v2'
  'Standard_L8s_v2'
  'Standard_L16s_v2'
  'Standard_L32s_v2'
  'Standard_L64s_v2'
  'Standard_L80s_v2'
  'Standard_NC6'
  'Standard_NC12'
  'Standard_NC24'
  'Standard_NC24r'
  'Standard_ND6s'
  'Standard_ND12s'
  'Standard_ND24s'
  'Standard_ND24rs'
  'Standard_NV6'
  'Standard_NV12'
  'Standard_NV24'
  'Standard_H8'
  'Standard_H16'
  'Standard_H16r'
  'Standard_H16mr'
  'Standard_HB120rs_v2'
  'Standard_HC44rs'
  'Standard_DC2s'
  'Standard_DC4s'
  'Standard_DC2s_v2'
  'Standard_DC4s_v2'
  'Standard_DC8s_v2'
  'Standard_DC16s_v2'
  'Standard_DC32s_v2'
  'Standard_A1_v2'
  'Standard_A2_v2'
  'Standard_A4_v2'
  'Standard_A8_v2'
  'Standard_A2m_v2'
  'Standard_A4m_v2'
  'Standard_A8m_v2'
])
param instanceType string = 'Standard_B2s' // Azure instance types.

@description('Username for the Virtual Machine.')
param adminUsername string

@description('Name of an existing SSH key to enable SSH access to the Deployment.')
@allowed([
  'sshPublicKey'
  'password'
])
param authenticationType string = 'sshPublicKey' // Existing SSH key pair name.

@description('SSH Key or password for the Virtual Machine. SSH key is recommended.')
@secure()
param adminPasswordOrKey string

//Condition for ipValid if is filled
var isEmptyIp = publicIpAddress == ''
var ipSegments = split(publicIpAddress, '.')
var isFourSegments = length(ipSegments) == 4
var seg1valid = isEmptyIp ? true : int(ipSegments[0]) >= 0 && int(ipSegments[0]) <= 255
var seg2valid = isEmptyIp ? true : int(ipSegments[1]) >= 0 && int(ipSegments[1]) <= 255
var seg3valid = isEmptyIp ? true : int(ipSegments[2]) >= 0 && int(ipSegments[2]) <= 255
var seg4valid = isEmptyIp ? true : int(ipSegments[3]) >= 0 && int(ipSegments[3]) <= 255
var isValidIP = !isEmptyIp && isFourSegments && seg1valid && seg2valid && seg3valid && seg4valid

//Condition for the domain name
var isEmptyDomain = domainName == ''
var domainParts = split(domainName, '.')
var validNumberParts = length(domainParts) >= 2
var allPartsValid = [
  for part in domainParts: length(part) >= 1 && length(part) <= 63 && !empty(part) && part == toLower(part) && !contains(
    part,
    '--'
  ) && empty(replace(part, '[a-z0-9-]', ''))
]

var isDomainValid = !isEmptyDomain && validNumberParts && !contains(allPartsValid, false)

var locationToLower = toLower(replace(location, ' ', '-'))

//Variables for deployment
var networkSettings = {
  privateIPaddressNetInterface: '10.0.0.5'
  vNetAddressPrefix: '10.0.0.0/16'
  subnetAddressPrefix: '10.0.0.0/24'
  netInterfaceName: '${stackName}-netInteface'
  vNetName: '${stackName}-vnet'
  subnetName: 'default'
}

var openviduVMSettings = {
  vmName: '${stackName}-VM-CE'
  osDiskType: 'StandardSSD_LRS'
  ubuntuOSVersion: {
    publisher: 'Canonical'
    offer: '0001-com-ubuntu-server-jammy'
    sku: '22_04-lts-gen2'
    version: 'latest'
  }
  linuxConfiguration: {
    disablePasswordAuthentication: true
    ssh: {
      publicKeys: [
        {
          path: '/home/${adminUsername}/.ssh/authorized_keys'
          keyData: adminPasswordOrKey
        }
      ]
    }
  }
}

var installScript = '''
#!/bin/bash -x
OPENVIDU_VERSION=main
DOMAIN=

apt-get update && apt-get install -y \
  curl \
  unzip \
  jq \
  wget

# Install aws-cli
# curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
# unzip -qq awscliv2.zip
# ./aws/install
# rm -rf awscliv2.zip aws

# Token for IMDSv2
# TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Configure Domain
if [[ "${domainName}" == '' ]]; then
  [ ! -d "/usr/share/openvidu" ] && mkdir -p /usr/share/openvidu
  #PublicHostname=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-hostname)
  DOMAIN=$PublicHostname
  echo $PublicHostname > /usr/share/openvidu/old-host-name
else
  DOMAIN=${domainName}
fi
# DOMAIN="$(/usr/local/bin/store_secret.sh save DOMAIN_NAME "$DOMAIN")"

# Store usernames and generate random passwords
REDIS_PASSWORD="$(/usr/local/bin/store_secret.sh generate REDIS_PASSWORD)"
MONGO_ADMIN_USERNAME="$(/usr/local/bin/store_secret.sh save MONGO_ADMIN_USERNAME "mongoadmin")"
MONGO_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate MONGO_ADMIN_PASSWORD)"
MINIO_ACCESS_KEY="$(/usr/local/bin/store_secret.sh save MINIO_ACCESS_KEY "minioadmin")"
MINIO_SECRET_KEY="$(/usr/local/bin/store_secret.sh generate MINIO_SECRET_KEY)"
DASHBOARD_ADMIN_USERNAME="$(/usr/local/bin/store_secret.sh save DASHBOARD_ADMIN_USERNAME "dashboardadmin")"
DASHBOARD_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate DASHBOARD_ADMIN_PASSWORD)"
GRAFANA_ADMIN_USERNAME="$(/usr/local/bin/store_secret.sh save GRAFANA_ADMIN_USERNAME "grafanaadmin")"
GRAFANA_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate GRAFANA_ADMIN_PASSWORD)"
DEFAULT_APP_USERNAME="$(/usr/local/bin/store_secret.sh save DEFAULT_APP_USERNAME "calluser")"
DEFAULT_APP_PASSWORD="$(/usr/local/bin/store_secret.sh generate DEFAULT_APP_PASSWORD)"
DEFAULT_APP_ADMIN_USERNAME="$(/usr/local/bin/store_secret.sh save DEFAULT_APP_ADMIN_USERNAME "calladmin")"
DEFAULT_APP_ADMIN_PASSWORD="$(/usr/local/bin/store_secret.sh generate DEFAULT_APP_ADMIN_PASSWORD)"
LIVEKIT_API_KEY="$(/usr/local/bin/store_secret.sh generate LIVEKIT_API_KEY "API" 12)"
LIVEKIT_API_SECRET="$(/usr/local/bin/store_secret.sh generate LIVEKIT_API_SECRET)"

# Base command
INSTALL_COMMAND="sh <(curl -fsSL http://get.openvidu.io/community/singlenode/$OPENVIDU_VERSION/install.sh)"

# Common arguments
COMMON_ARGS=(
  "--no-tty"
  "--install"
  "--environment=aws"
  "--deployment-type=single_node"
  "--domain-name=$DOMAIN"
  "--enabled-modules=observability,app"
  "--redis-password=$REDIS_PASSWORD"
  "--mongo-admin-user=$MONGO_ADMIN_USERNAME"
  "--mongo-admin-password=$MONGO_ADMIN_PASSWORD"
  "--minio-access-key=$MINIO_ACCESS_KEY"
  "--minio-secret-key=$MINIO_SECRET_KEY"
  "--dashboard-admin-user=$DASHBOARD_ADMIN_USERNAME"
  "--dashboard-admin-password=$DASHBOARD_ADMIN_PASSWORD"
  "--grafana-admin-user=$GRAFANA_ADMIN_USERNAME"
  "--grafana-admin-password=$GRAFANA_ADMIN_PASSWORD"
  "--default-app-user=$DEFAULT_APP_USERNAME"
  "--default-app-password=$DEFAULT_APP_PASSWORD"
  "--default-app-admin-user=$DEFAULT_APP_ADMIN_USERNAME"
  "--default-app-admin-password=$DEFAULT_APP_ADMIN_PASSWORD"
  "--livekit-api-key=$LIVEKIT_API_KEY"
  "--livekit-api-secret=$LIVEKIT_API_SECRET"
)

# Turn with TLS
if [[ "${TurnDomainName}" != '' ]]; then
  LIVEKIT_TURN_DOMAIN_NAME=$(/usr/local/bin/store_secret.sh save LIVEKIT_TURN_DOMAIN_NAME "${TurnDomainName}")
  COMMON_ARGS+=(
    "--turn-domain-name=$LIVEKIT_TURN_DOMAIN_NAME"
  )
fi

# Certificate arguments
if [[ "${CertificateType}" == "selfsigned" ]]; then
  CERT_ARGS=(
    "--certificate-type=selfsigned"
  )
elif [[ "${CertificateType}" == "letsencrypt" ]]; then
  LETSENCRYPT_EMAIL=$(/usr/local/bin/store_secret.sh save LETSENCRYPT_EMAIL "${LetsEncryptEmail}")
  CERT_ARGS=(
    "--certificate-type=letsencrypt"
    "--letsencrypt-email=$LETSENCRYPT_EMAIL"
  )
else
  # Download owncert files
  mkdir -p /tmp/owncert
  wget -O /tmp/owncert/fullchain.pem ${OwnPublicCertificate}
  wget -O /tmp/owncert/privkey.pem ${OwnPrivateCertificate}

  # Convert to base64
  OWN_CERT_CRT=$(base64 -w 0 /tmp/owncert/fullchain.pem)
  OWN_CERT_KEY=$(base64 -w 0 /tmp/owncert/privkey.pem)

  CERT_ARGS=(
    "--certificate-type=owncert"
    "--owncert-public-key=$OWN_CERT_CRT"
    "--owncert-private-key=$OWN_CERT_KEY"
  )

  # Turn with TLS and own certificate
  if [[ "${TurnDomainName}" != '' ]]; then
    # Download owncert files
    mkdir -p /tmp/owncert-turn
    wget -O /tmp/owncert-turn/fullchain.pem ${TurnOwnPublicCertificate}
    wget -O /tmp/owncert-turn/privkey.pem ${TurnOwnPrivateCertificate}

    # Convert to base64
    OWN_CERT_CRT_TURN=$(base64 -w 0 /tmp/owncert-turn/fullchain.pem)
    OWN_CERT_KEY_TURN=$(base64 -w 0 /tmp/owncert-turn/privkey.pem)

    CERT_ARGS+=(
      "--turn-owncert-private-key=$OWN_CERT_KEY_TURN"
      "--turn-owncert-public-key=$OWN_CERT_CRT_TURN"
    )
  fi
fi

# Construct the final command with all arguments
FINAL_COMMAND="$INSTALL_COMMAND $(printf "%s " "${!COMMON_ARGS[@]}") $(printf "%s " "${!CERT_ARGS[@]}")"

# Install OpenVidu
exec bash -c "$FINAL_COMMAND"
'''

resource openviduServer 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: openviduVMSettings.vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: instanceType
    }
    storageProfile: {
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: openviduVMSettings.osDiskType
        }
      }
      imageReference: openviduVMSettings.ubuntuOSVersion
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: netInterface_OV.id
        }
      ]
    }
    osProfile: {
      computerName: openviduVMSettings.vmName
      adminUsername: adminUsername
      adminPassword: adminPasswordOrKey
      linuxConfiguration: ((authenticationType == 'password') ? null : openviduVMSettings.linuxConfiguration)
    }
  }
}

//Create publicIPAddress if convinient
resource publicIP_OV 'Microsoft.Network/publicIPAddresses@2023-11-01' = if (isEmptyIp == true) {
  name: '${stackName}-publicIP'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAddressVersion: 'IPv4'
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: isEmptyDomain ? '${toLower(stackName)}' : domainName
    }
  }
}

resource publicIP_OV_ifEmpty 'Microsoft.Network/publicIPAddresses@2023-11-01' existing = if (isEmptyIp == false) {
  name: publicIpAddressResourceName
}

// Create the virtual network
resource vnet_OV 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: networkSettings.vNetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        networkSettings.vNetAddressPrefix
      ]
    }
    subnets: [
      {
        name: networkSettings.subnetName
        properties: {
          addressPrefix: networkSettings.subnetAddressPrefix
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
          networkSecurityGroup: {
            id: webServerSecurityGroup.id
          }
        }
      }
    ]
  }
}

resource netInterface_OV 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: networkSettings.netInterfaceName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet_OV.name, networkSettings.subnetName)
          }
          publicIPAddress: {
            id: isEmptyIp ? publicIP_OV.id : publicIP_OV_ifEmpty.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: webServerSecurityGroup.id
    }
  }
}

// SecurityGroup for OpenviduSN
resource webServerSecurityGroup 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${stackName}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'SSH'
        properties: {
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'HTTP'
        properties: {
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'HTTPS'
        properties: {
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
      {
        name: 'TURN'
        properties: {
          protocol: 'Udp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          access: 'Allow'
          priority: 130
          direction: 'Inbound'
        }
      }
      {
        name: 'RTMP'
        properties: {
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '1935'
          access: 'Allow'
          priority: 140
          direction: 'Inbound'
        }
      }
      {
        name: 'WebRTC_over_TCP'
        properties: {
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '7881'
          access: 'Allow'
          priority: 150
          direction: 'Inbound'
        }
      }
      {
        name: 'WebRTC_using_WHIP'
        properties: {
          protocol: 'Udp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '7885'
          access: 'Allow'
          priority: 160
          direction: 'Inbound'
        }
      }
      {
        name: 'MinIO'
        properties: {
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '9000'
          access: 'Allow'
          priority: 170
          direction: 'Inbound'
        }
      }
      {
        name: 'WebRTC_traffic_UDP'
        properties: {
          protocol: 'Udp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: [
            '50000'
            '60000'
          ]
          access: 'Allow'
          priority: 180
          direction: 'Inbound'
        }
      }
      {
        name: 'WebRTC_traffic_TCP'
        properties: {
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: [
            '50000'
            '60000'
          ]
          access: 'Allow'
          priority: 190
          direction: 'Inbound'
        }
      }
    ]
  }
}

output ipValidationStatus string = isValidIP ? 'IP address is valid' : 'IP address not valid'

output domainValidationStatus string = isDomainValid ? 'Domain is valid' : 'Domain is not valid'

//Condition if owncert is selected
output ownCertValidationStatus string = (certificateType == 'owncert' && ownPrivateCertificate != '' && ownPublicCertificate != '')
  ? 'owncert selected and valid'
  : 'You need to fill \'Own Public Certificate\' and \'Own Private Certificate\''

//Condition if letsEncrypt is selected
output letsEncryptValidationStatus string = (certificateType == 'letsencrypt' && letsEncryptEmail != '')
  ? 'letsEncrypt selected and valid'
  : 'You need to fill \'Lets Encrypt Email\''
