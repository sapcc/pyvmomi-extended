# Extension for `pyVmomi`

This library adds the following extensions to `pyVmomi`:
* a subset of the `ssoadmin` API implemented partly by reading the
  publicly-available implementation in `vmware/govmomi`, partly by trial and
  error
* `HostVMotionManagerVMotionResult` objects used in tasks
* `QueryProfileResultInternal` objects sometimes returnedby Pbm

**Attention:** None of these extensions contain proper version information.
Some of the return types are guess-work.  This library is not production-ready.

## Enabling the extension of `pyVmomi`
```python
from pyvmomi_extended import extend_pyvmomi

extend_pyvmomi()
```

## Getting a SAML token
```python
from pyVim import sso

domain = 'vsphere.local'
auth = sso.SsoAuthenticator(f"https://{host}/sts/STSService/{domain}")
saml_token = auth.get_bearer_saml_assertion(user, password, delegatable=True)
```


## Using the sso APIs
You first have to enble the extension of `pyVmomi` and get a SAML token, then you can run this:
```python
from pyVmomi import SoapStubAdapter, sso
from pyvmomi_extended import SSO_VERSION

stub = SoapStubAdapter(
	host=host,
	port=443,
	version=SSO_VERSION,
	path="/sso-adminserver/sdk/vsphere.local",
	samlToken=saml_token,
	poolSize=0
)

sessionManager = sso.SsoSessionManager("ssoSessionManager", stub=stub)
sessionManager.Login()

# we do not need to send the token anymore - makes for smaller requests
stub.samlToken = None

si = sso.SsoAdminServiceInstance('SsoAdminServiceInstance', stub=stub)
```
