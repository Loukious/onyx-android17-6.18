"""Keep RNDIS control and netdev cleanup ahead of IPA unregistration."""
from pathlib import Path
import re
import unittest


DRIVER = Path(__file__).resolve().parents[2] / 'modules/drivers/usb/gadget/function/f_gsi.c'


class GsiRndisTeardownTests(unittest.TestCase):
    def test_unbind_drops_netdev_reference_before_ipa_deinit(self):
        unbind = re.search(r'(?ms)^static void gsi_unbind\([^\n]*\)\n\{.*?^\}',
                           DRIVER.read_text())
        self.assertIsNotNone(unbind)
        statements = (
            'gsi_disable(f);',
            'usb_ep_dequeue(',
            'gsi_ipa_token_retire(gsi);',
            'cancel_delayed_work_sync(&gsi->d_port.usb_ipa_w);',
            'rndis_deregister(gsi->params);',
            'gsi->params = NULL;',
            'dev_put(gsi->net);',
            'gsi->net = NULL;',
            'gsi->d_port.ipa_ops->deinit_teth_prot(gsi->prot_id);',
        )
        body = unbind[0]
        positions = [body.index(statement) for statement in statements]

        self.assertEqual(positions, sorted(positions))
