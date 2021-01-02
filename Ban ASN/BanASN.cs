using System;
using System.Net;
using System.Windows.Forms;
using Vanara.PInvoke;

namespace Ban_ASN
{
    public partial class BanASN : Form
    {
        public BanASN()
        {
            InitializeComponent();
        }

        private WebClient client = new WebClient();

        public static FirewallApi.INetFwPolicy2 firewallPolicy = (FirewallApi.INetFwPolicy2)Activator.CreateInstance(
            Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

        public static string ApplyFirewallRule(string ASN, string IP, bool ban)
        {
            try
            {
                string SanitizedIP = IP.Replace("\r", "").Replace("\n", "").Replace(" ", "");

                string RuleName = "ASN: " + ASN + " Block - IP Count: " + SanitizedIP.Split(',').Length;

                bool Exists = false;
                FirewallApi.INetFwRule ExistingRule = null;

                foreach (FirewallApi.INetFwRule rule in firewallPolicy.Rules)
                {
                    if (rule == null)
                    {
                        continue;
                    }

                    if (rule.Name.Contains("ASN: " + ASN + " Block"))
                    {
                        Exists = true;
                        ExistingRule = rule;
                        break;
                    }

                }

                if (ban)
                {
                    if (Exists)
                    {
                        ExistingRule.Name = RuleName;
                        ExistingRule.RemoteAddresses = SanitizedIP;
                        ExistingRule.Description = "Banned ASN: " + ASN + " - IP Count: " + SanitizedIP.Split(',').Length;

                        return "Result: Updated Existing Rule!";
                    }

                    FirewallApi.INetFwRule firewallRule = (FirewallApi.INetFwRule)Activator.CreateInstance(
                        Type.GetTypeFromProgID("HNetCfg.FWRule"));

                    firewallRule.Action = FirewallApi.NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    firewallRule.Direction = FirewallApi.NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN;
                    firewallRule.InterfaceTypes = "All";

                    firewallRule.Name = RuleName;
                    firewallRule.Description = "Banned ASN: " + ASN + " - IP Count: " + SanitizedIP.Split(',').Length;
                    firewallRule.RemoteAddresses = SanitizedIP;

                    firewallRule.Enabled = true;

                    firewallPolicy.Rules.Add(firewallRule);

                    return "Result: Created Rule!";
                }

                if (Exists)
                {
                    firewallPolicy.Rules.Remove(ExistingRule.Name);

                    return "Result: Removed Rule!";
                }

                return "Result: Rule Does Not Exist In The First Place!";
            }
            catch
            {
                return "Result: Failure!";
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textBox1.Text) || !int.TryParse(textBox1.Text, out int test))
            {
                MessageBox.Show("You Must Specify An ASN!");
                return;
            }

            string[] result = client.DownloadString(
                "https://www.enjen.net/asn-blocklist/index.php?asn=" + textBox1.Text + "&type=iplist&api=1").Split('\n');

            if (result.Length < 2)
            {
                MessageBox.Show("ASN Not Valid!");
                return;
            }

            int ruleCount = (int)Math.Max(0, (result.Length - 5000)) + 1;

            for (int i = 0; i < ruleCount; i++)
            {
                string ranges = result[((i) * 5000)];

                for (var index = ((i) * 5000); index < result.Length; index++)
                {
                    string ip = result[index];

                    if (!string.IsNullOrEmpty(ip) && !ranges.Contains(ip))
                    {
                        ranges = ranges + "," + ip;
                    }
                }

                if (ranges.Length < 1)
                {
                    MessageBox.Show("ASN Not Valid!");
                    return;
                }

                MessageBox.Show(ApplyFirewallRule(textBox1.Text + (ruleCount > 1 ? " [" + i + "]" : ""), ranges, true));
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textBox1.Text) || !int.TryParse(textBox1.Text, out int test))
            {
                MessageBox.Show("You Must Specify An ASN!");
                return;
            }

            string[] result = client.DownloadString(
                "https://www.enjen.net/asn-blocklist/index.php?asn=" + textBox1.Text + "&type=iplist&api=1").Split('\n');

            if (result.Length < 2)
            {
                MessageBox.Show("ASN Not Valid!");
                return;
            }

            int ruleCount = (int)Math.Max(0, (result.Length - 5000)) + 1;

            for (int i = 0; i < ruleCount; i++)
            {
                string ranges = result[((i) * 5000)];

                for (var index = ((i) * 5000); index < result.Length; index++)
                {
                    string ip = result[index];

                    if (!string.IsNullOrEmpty(ip) && !ranges.Contains(ip))
                    {
                        ranges = ranges + "," + ip;
                    }
                }

                if (ranges.Length < 1)
                {
                    MessageBox.Show("ASN Not Valid!");
                    return;
                }

                MessageBox.Show(ApplyFirewallRule(textBox1.Text + (ruleCount > 1 ? " [" + i + "]" : ""), ranges, false));
            }
        }
    }
}
