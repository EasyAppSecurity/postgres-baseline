Postgre installation Security Assessment InSpec profile

## Standalone Usage

1. Install [InSpec](https://github.com/chef/inspec) for the profile execution

2. Clone the repository
```
$ git clone https://github.com/rusakovichma/postgres-baseline

```
3. Create properties .yml file in postgre-baseline/attributes folder, where specify postgre installation settings. 
For example, centos7-test-attributes.yml:
```
user : postgres  <-- postgre superuser name
appuser : appuser  <-- application user account name
postgres_data : /var/lib/pgsql/data  <-- pg data directory path
postgres_conf_dir : /var/lib/pgsql/data   <-- pg configuration directory path
postgres_conf_path : /var/lib/pgsql/data/postgresql.conf   <-- postgresql.conf file path

```
4. Execute the profile:
 - **Specifying the superuser password directly:**
	```
	$ inspec exec postgres-baseline --input user_password='superuser_pass' --input-file postgres-baseline/attributes/centos7-test-attributes.yml --reporter html:/tmp/pg-inspec-baseline.html

	``` 
	
	
 - **(Recommended) Or obtain the superuser password from [HashiCorp Vault](https://www.vaultproject.io/)**: 
    - Install [InSpec Vault](https://github.com/inspec/inspec-vault) plugin:
	```
	$ inspec plugin install inspec-vault

	```    
	- Ensure two environment variables are set for the plugin:
	```
	VAULT_TOKEN – set to your authentication token. Contact your Vault administrator for instructions.
	VAULT_ADDR – set to the URL of your vault server, including the port.
	
	```
	- Put PG superuser password in Vault profile space:
	```
	$ vault kv put secret/inspec/postgres-baseline user_password=pg_superuser_pass

	``` 
	- Run the profile:
	```
	$ inspec exec postgres-baseline --input-file postgres-baseline/attributes/centos7-test-attributes.yml --reporter html:/tmp/pg-inspec-baseline.html

	``` 

5. Report of the baseline assessment will be at /tmp/pg-inspec-baseline.html


## License and Author

- Author:: Patrick Muench <patrick.muench1111@gmail.com >
- Author:: Dominik Richter <dominik.richter@googlemail.com>
- Author:: Christoph Hartmann <chris@lollyrock.com>
- Author:: Edmund Haselwanter <me@ehaselwanter.com>

- Copyright 2014-2019, The DevSec Hardening Framework Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
