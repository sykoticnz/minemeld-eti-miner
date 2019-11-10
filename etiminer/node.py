import logging
import os
import collections
from datetime import datetime, timedelta

import pytz
import yaml

from minemeld.ft.basepoller import BasePollerFT
from minemeld.ft.utils import interval_in_sec

from cabby import create_client 
from .stix import decode as stix_decode

LOG = logging.getLogger(__name__)

'''
STIX/TAXII client for MineMeld. Uses cabby library. 
Based on the default taxii and taxii-ng implementation. 

IMPROVEMENTS:
1) Uses cabby library, so no more messing around with requests. Better support.
2) Added parameters voor cert based authentication
3) parameters for specifying poll service manually
4) parameters for port and version and http or https


@Author: Brad Pearpoint
@Copied from: mr torgue
'''
class Miner(BasePollerFT):
    def __init__(self, name, chassis, config):
        self.discovered_poll_service = None
        self.last_taxii_run = None
        self.last_stix_package_ts = None
        self.last_taxii_content_ts = None
        self.api_key = None

        super(Miner, self).__init__(name, chassis, config)

    def configure(self):
        super(Miner, self).configure()

        self.verify_cert = self.config.get('verify_cert', True)
        self.polling_timeout = self.config.get('polling_timeout', 20)

        self.initial_interval = self.config.get('initial_interval', '1d')
        self.initial_interval = interval_in_sec(self.initial_interval)
        if self.initial_interval is None:
            LOG.error(
                '%s - wrong initial_interval format: %s',
                self.name, self.initial_interval
            )
            self.initial_interval = 86400
        self.max_poll_dt = self.config.get(
            'max_poll_dt',
            86400
        )

        # options for processing
        self.ip_version_auto_detect = self.config.get('ip_version_auto_detect', True)
        self.ignore_composition_operator = self.config.get('ignore_composition_operator', False)
        self.create_fake_indicator = self.config.get('create_fake_indicator', False)
        self.lower_timestamp_precision = self.config.get('lower_timestamp_precision', False)

        self.discovery_service = self.config.get('discovery_service', None)
        self.poll_service = self.config.get('poll_service', None)
        self.collection = self.config.get('collection', None)
        self.host = self.config.get('host', None)

        self.side_config_path = os.path.join(
            os.environ['MM_CONFIG_DIR'],
            '%s_side_config.yml' % self.name
        )

        self.prefix = self.config.get('prefix', None)

        self.confidence_map = self.config.get('confidence_map', {
            'low': 40,
            'medium': 60,
            'high': 80
        })

        # authentication
        self.api_key = self.config.get('api_key', None)
        self.api_header = self.config.get('api_header', None)
        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)
        self.cert_file = self.config.get('cert_file', None)
        self.key_file = self.config.get('key_file', None)

        # misc settings
        self.use_https = self.config.get('use_https', True)
        self.port = self.config.get('port', 443)
        self.version = self.config.get('version', "1.1")

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        api_key = sconfig.get('api_key', None)
        api_header = sconfig.get('api_header', None)
        if api_key is not None and api_header is not None:
            self.api_key = api_key
            self.api_header = api_header
            LOG.info('{} - Loaded API credentials from side config'.format(self.name))

        username = sconfig.get('username', None)
        password = sconfig.get('password', None)
        cert_file = sconfig.get('cert_file', None)
        key_file = sconfig.get('key_file', None)
        if username is not None and password is not None:
            self.username = username
            self.password = password
            LOG.info('{} - Loaded Basic authentication credentials from side config'.format(self.name))

        verify_cert = sconfig.get('verify_cert', None)
        if verify_cert is not None:
            self.verify_cert = verify_cert
            LOG.info('{} - Loaded verify cert from side config'.format(self.name))

    def _saved_state_restore(self, saved_state):
        super(Miner, self)._saved_state_restore(saved_state)
        self.last_taxii_run = saved_state.get('last_taxii_run', None)
        LOG.info('last_taxii_run from sstate: %s', self.last_taxii_run)

    def _saved_state_create(self):
        sstate = super(Miner, self)._saved_state_create()
        sstate['last_taxii_run'] = self.last_taxii_run

        return sstate

    def _saved_state_reset(self):
        super(Miner, self)._saved_state_reset()
        self.last_taxii_run = None

    def _process_item(self, item):
        indicator = item.pop('indicator')
        value = {}
        for k, v in item.iteritems():
            if k.startswith('stix_') and self.prefix is not None:
                k = self.prefix + k[4:]
            value[k] = v

        return [[indicator, value]]

    '''
    this function should not be needed because cabby does this in it's own code.
    create because this was the default behaviour
    '''
    def _discover_poll_service(self, client):
        return client.get_services(service_type="POLL")[0].address

    '''
    polls specified collection. No more messing around with raw requests. cabby returns a list with blocks.
    The ng stix parser can be used to collect IOC's
    '''
    def _poll_collection(self, client, poll_service, begin, end):
        results = client.poll(self.collection, uri=poll_service, begin_date=begin, end_date=end)
        LOG.info('{} - polling {} from {!r} to {!r}'.format(self.name, poll_service, begin, end))
        # parse results for IOC's
        for result in results:
            timestamp = result.timestamp
            _, indicators = stix_decode(result.content)
            for indicator in indicators:
                yield indicator
            # update last stix package
            if self.last_stix_package_ts is None or timestamp > self.last_stix_package_ts:
                LOG.debug('{} - last package ts: {!r}'.format(self.name, timestamp))
                self.last_stix_package_ts = timestamp



    def _incremental_poll_collection(self, client, poll_service, begin, end):
        cbegin = begin
        dt = timedelta(seconds=self.max_poll_dt)

        self.last_stix_package_ts = None
        self.last_taxii_content_ts = None

        while cbegin < end:
            cend = min(end, cbegin+dt)

            LOG.info('{} - polling {!r} to {!r}'.format(self.name, cbegin, cend))
            result = self._poll_collection(client=client, poll_service=poll_service, begin=cbegin, end=cend)

            for i in result:
                yield i

            if self.last_taxii_content_ts is not None:
                self.last_taxii_run = self.last_taxii_content_ts

            cbegin = cend

    '''
    builds the stix taxii iterator
    '''
    def _build_iterator(self, now):
        # create cabby client
        LOG.info('{} - Creating a cabby client with host={}, discovery={}, port={}, https={} and version={}'.format(self.name, self.host, self.discovery_service, self.port, self.use_https, self.version))
        client = create_client(host=self.host, discovery_path=self.discovery_service, port=self.port, use_https=self.use_https, version=self.version)
        # basic authentication
        client.set_auth(username=self.username, password=self.password, cert_file=self.cert_file, key_file=self.key_file)
        if self.poll_service is not None:
            discovered_poll_service = self.poll_service
        else:
            discovered_poll_service = self._discover_poll_service(client)

        LOG.debug('{} - poll service: {!r}'.format(self.name, discovered_poll_service))

        last_run = self.last_taxii_run
        if last_run is None:
            last_run = now-(self.initial_interval*1000)

        begin = datetime.utcfromtimestamp(last_run/1000)
        begin = begin.replace(microsecond=0, tzinfo=pytz.UTC)

        end = datetime.utcfromtimestamp(now/1000)
        end = end.replace(tzinfo=pytz.UTC)

        if self.lower_timestamp_precision:
            end = end.replace(second=0, microsecond=0)
            begin = begin.replace(second=0, microsecond=0)

        return self._incremental_poll_collection(
            client,
            discovered_poll_service,
            begin=begin,
            end=end
        )

    def _flush(self):
        self.last_taxii_run = None
        super(Miner, self)._flush()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Miner, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        BasePollerFT.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except Exception:
            pass
