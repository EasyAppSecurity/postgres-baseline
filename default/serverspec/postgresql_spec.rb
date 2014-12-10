# encoding: utf-8

require 'spec_helper'

ENV['PGPASSWORD'] = 'iloverandompasswordsbutthiswilldo'

RSpec::Matchers.define :match_key_value do |key, value|
  match do |actual|
    actual =~ /^\s*?#{key}\s*?=\s*?#{value}/
  end
end

# set OS-dependent filenames and paths
case os[:family]
when 'ubuntu', 'debian'
  postgres_home = '/var/lib/postgresql'
  service_name = 'postgresql'
  task_name = 'postgresql.conf'
  user_name = 'postgres'
  postgres_version = command('ls /etc/postgresql/').stdout.chomp
  config_path = "/etc/postgresql/#{postgres_version}/main"

else
  postgres_home = '/var/lib/postgresql'
  service_name = 'postgresql'
  task_name = 'postmaster'
  user_name = 'postgres'
  config_path = '/var/lib/pgsql/data'
end

describe service("#{service_name}") do
  it { should be_enabled }
  it { should be_running }
end

hba_config_file = "#{config_path}/pg_hba.conf"
postgres_config_file = "#{config_path}/postgresql.conf"
psql_command = "sudo -u postgres -i PGPASSWORD='#{ENV['PGPASSWORD']}' psql"


describe command('sudo -i psql -V') do
  its(:stdout) { should_not match(/RC/) }
  its(:stdout) { should_not match(/DEVEL/) }
  its(:stdout) { should_not match(/BETA/) }
end


describe command("ps aux | grep #{task_name} | grep -v grep | wc -l") do
  its(:stdout) { should match(/^1/) }
end

describe 'Checking Postgres-databases for risky entries' do

  
  describe command("#{psql_command} -d postgres -c \"SELECT count (*) FROM pg_language WHERE lanpltrusted = 'f' AND lanname!='internal' AND lanname!='c';\" | tail -n3 | head -n1 | tr -d ' '") do
    its(:stdout) { should match(/^0/) }
  end

  
  describe command("#{psql_command} -d postgres -c \"SELECT * FROM pg_shadow WHERE passwd IS NULL;\" | tail -n2 | head -n1 | cut -d '(' -f2 | cut -d ' ' -f1") do
    its(:stdout) { should match(/^0/) }
  end

  
  describe command("#{psql_command} -d psql -d postgres -c \"SELECT passwd FROM pg_shadow;\" | tail -n+3 | head -n-2 | grep -v \"md5\" -c") do
    its(:stdout) { should match(/^0/) }
  end

  
  describe command("#{psql_command} -d postgres -c \"SELECT rolname,rolsuper,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolsuper IS TRUE OR rolcreaterole IS TRUE or rolcreatedb IS TRUE;\" | tail -n+3 | head -n-2 | wc -l") do
    its(:stdout) { should match(/^1/) }
  end

  
  describe command("#{psql_command} -d postgres -c \"\\dp pg_catalog.pg_authid\" | grep pg_catalog | wc -l") do
    its(:stdout) { should match(/^1/) }
  end

end


describe 'Postgres FS-permissions' do

  describe command("sudo find #{postgres_home} -user #{user_name} -group #{user_name} -perm /go=rwx | wc -l") do
    its(:stdout) { should match(/^0/) }
  end

end

describe 'Parsing configfiles' do

  
  describe file(postgres_config_file) do
    its(:content) { should match_key_value('ssl', 'off') }
  end

  
  describe file(postgres_config_file) do
    its(:content) { should match_key_value('ssl_ciphers', "'ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH'") }
  end

  
  describe file(postgres_config_file) do
    its(:content) { should match_key_value('password_encryption', 'on') }
  end

  
  describe 'require MD5 for ALL users, peers in pg_hba.conf' do

    describe file(hba_config_file) do
      its(:content) { should match(/local\s.*?all\s.*?all\s.*?md5/) }
    end

    describe file(hba_config_file) do
      its(:content) { should match(/host\s.*?all\s.*?all\s.*?127.0.0.1\/32\s.*?md5/) }
    end

    describe file(hba_config_file) do
      its(:content) { should match(/host\s.*?all\s.*?all\s.*?::1\/128\s.*?md5/) }
    end

    
    # We accept one peer and one ident for now (chef automation)

    describe command("sudo -i cat #{hba_config_file} | egrep 'peer|ident' | wc -l") do
      its(:stdout) { should match(/^[2|1]/) }
    end

    describe command("sudo -i cat #{hba_config_file} | egrep 'trust|password|crypt' | wc -l") do
      its(:stdout) { should match(/^0/) }
    end

  end

  
  describe 'System Monitoring' do

    describe file(postgres_config_file) do
      its(:content) { should match_key_value('logging_collector', 'on') }
      its(:content) { should match(/log_directory\s.*?pg_log/) } # match pg_log and 'pg_log'
      its(:content) { should match_key_value('log_connections', 'on') }
      its(:content) { should match_key_value('log_disconnections', 'on') }
      its(:content) { should match_key_value('log_duration', 'on') }
      its(:content) { should match_key_value('log_hostname', 'on') }
      its(:content) { should match_key_value('log_line_prefix', "'%t %u %d %h'") }
    end

  end

end
