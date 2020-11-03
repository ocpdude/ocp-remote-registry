
# Building an OpenShift Disconnected Registry on Azure
##### NOTE: Azure uses a .vhd image, you can download this manually from cloud.redhat.com or use the Azure upload steps referenced in the UPI build instructions contained in this repo.

The video demo of this install can be found on YouTube here : (part 1: https://youtu.be/e0whE0SnHfY) & (part 2: https://youtu.be/dMUX0c29988)


## We need to create a directory to hold the disconnected registry.

0. Install podman : https://podman.io/getting-started/installation \
*You will also need packages: curl, wget & jq (ubuntu: apache2-utils or centos: httpd-tools)

1. We will need to create/establish a CA and Server Certificate for the install, the  CA certificate will be installed in our install-config.yaml and the registry will host the server certificate. If this step isn't done, TLS errors will prevent nodes from connecting and downloading packages. The CA and Server cert our out of scope for this document; however, self-signed procedures can be found here: \
https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/

2. A note on firewalls, if your registry server does have an active firewall permit tcp/5000

    `ex: (ubuntu) sudo ufw allow 5000/tcp`\
    `ex: (centos) firewall-cmd --add-port=5000/tcp --permanent`

3. Create the directories you'll need to run the registry. These directories will be mounted in the container running the registry.

    `sudo mkdir -p /opt/registry/{auth,certs,data}`

4. Generate a username and password (must use bcrypt formatted passwords), for access to your registry.

    `sudo htpasswd -bBc /opt/registry/auth/htpasswd <name> <password>`

5. Start the container registry \
i. Your server cert and key should be located in /opt/regsitry/certs named registry.crt & registry.key. \
ii. Append any self-signed CA to your registry.crt, ie: cat server.crt ca.crt > registry.crt \
iii. registry.key should be chmod 400.
    ```
    sudo podman run -d --name poc-registry -p 5000:5000 \
    -v /opt/registry/data:/var/lib/registry:z \
    -v /opt/registry/auth:/auth:z \
    -e "REGISTRY_AUTH=htpasswd" \
    -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry" \
    -e "REGISTRY_HTTP_SECRET=ALongRandomSecretForRegistry" \
    -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
    -v /opt/registry/certs:/certs:z \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt \
    -e REGISTRY_HTTP_TLS_KEY=/certs/registry.key \
    docker.io/library/registry:2
    ```
6. Test connectivity to the registry, this should return an "empty" repo.\
NOTE: Make sure you've installed your CA \
*Ubuntu: sudo cp CA.crt /usr/share/ca-certificates/CA.crt && sudo dpkg-reconfigure ca-certificates \
*CentOS: sudo cp CA.crt /etc/pki/ca-trust/source/anchors/CA.crt && update-ca-trust extract

    `curl -u <name>:<password> -k https://registry.ocp4.example.com:5000/v2/_catalog`

    Expected result: {"repositories":[]}

7. Start and top the registry with \
    `sudo podman stop poc-registry`\
    `sudo podman start poc-registry`

8. Installing the OpenShift Binaries

    `export BUILDNUMBER=$(curl -s https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/release.txt | grep 'Name:' | awk '{print $NF}')`

    `echo $BUILDNUMBER`

    Download the client and install tools:\
        `sudo wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-client-linux-${BUILDNUMBER}.tar.gz -P /opt/registry`

      `sudo wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-install-linux-${BUILDNUMBER}.tar.gz -P /opt/registry`

    Extract them to your registry host:\
    `sudo tar -xzf /opt/registry/openshift-client-linux-${BUILDNUMBER}.tar.gz -C /usr/local/bin/`

    `sudo tar -xzf /opt/registry/openshift-install-linux-${BUILDNUMBER}.tar.gz -C /usr/local/bin/`

9. Setup Mirroring into the Registry\
Refer to: https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/release.txt
    ```
    export REGISTRY_HOME="/opt/registry"
    export OCP_RELEASE="4.6.1-x86_64"
    export LOCAL_REGISTRY="registry.private.example.com:5000"
    export RELEASE_NAME="ocp-release"
    export LOCAL_REPO="ocp4/openshift4"
    export UPSTREAM_REPO="openshift-release-dev"
    export LOCAL_SECRET_JSON="${HOME}/pull-secret-2.json"
    ```
10. Setup Registry Authentication

    Encode your credentials\
    ```
    export REG_SECRET=`echo -n <name>:<password> | base64 -w0`
    ```
    Add this output to your pull-secret authenication chain.

    `cat pull-secret | jq '.auths += {"registry.private.example.com:5000": {"auth": "REG_SECRET","email": "shaker@email.com"}}' | sed "s/REG_SECRET/$REG_SECRET/" > pull-secret-2.json`

11. Start Mirroring
    ```
    oc adm release mirror -a ${LOCAL_SECRET_JSON} \
    --from=quay.io/${UPSTREAM_REPO}/${RELEASE_NAME}:${OCP_RELEASE} \
    --to-release-image=${LOCAL_REGISTRY}/${LOCAL_REPO}:${OCP_RELEASE} \
    --to=${LOCAL_REGISTRY}/${LOCAL_REPO}
    ```

12. USING this Registry

    i. In your generated install-config.yaml enter your registry specific pull-secret
    ```
    pullSecret: '{"auths":{"registry.private.example.com:5000": {"auth": "c2hha2VyOnJlZGhhdA==","email": "shaker@email.com"}}}'
    ```
    ii. Add your CA.crt 
    ```
    echo "additionalTrustBundle: |" >> redwagon/install-config.yaml
    cat ca.crt | sed 's/^/\ \ \ \ \ /g' >> redwagon/install-config.yaml
    ```
    iii. Add your ssh public key
    ```
    echo -n "sshKey: '" >> private/install-config.yaml && cat ~/.ssh/id_rsa.pub | sed "s/$/\'/g" >> redwagon/install-config.yaml
    ```

    iv. To use the new mirrored repository to install, add the following section to the install-config.yaml:

    ```
    imageContentSources:
    - mirrors:
      - registry.private.example.com:5000/ocp4/openshift4
      source: quay.io/openshift-release-dev/ocp-release
    - mirrors:
      - registry.private.example.com:5000/ocp4/openshift4
      source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
    ```

13. To use the new mirrored repository for upgrades, use the following to create an ImageContentSourcePolicy:
```
apiVersion: operator.openshift.io/v1alpha1
kind: ImageContentSourcePolicy
metadata:
  name: example
spec:
  repositoryDigestMirrors:
  - mirrors:
    - registry.private.example.com:5000/ocp4/openshift4
    source: quay.io/openshift-release-dev/ocp-release
  - mirrors:
    - registry.private.example.com:5000/ocp4/openshift4
    source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
```

14. Begin your install as IPI or UPI
openshift-install create manifests --dir=`<DIR>`\
...\
...\
etc.

#### Thanks and references used for this tutorial:
openshift version information: https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/release.txt\
disconnected install: https://www.openshift.com/blog/openshift-4-2-disconnected-install\
air gap notes: https://medium.com/@two.oes/openshift-4-in-an-air-gap-disconnected-environment-part-2-installation-1dd8bf085fdd
https://www.cyberciti.biz/faq/how-to-configure-ufw-to-forward-port-80443-to-internal-server-hosted-on-lan/
