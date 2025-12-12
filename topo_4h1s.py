#!/usr/bin/python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class FourHostOneSwitch(Topo):
    """
    拓樸：
        h1 --\
        h2 ---- s1
        h3 --/
        h4 --/
    IP: 10.0.0.[1-4]/24
    MAC: 00:00:00:00:00:[01-04]
    """

    def build(self):
        # 關鍵：failMode='standalone'，沒有 controller 也會像一般交換機一樣轉封包
        s1 = self.addSwitch('s1', cls=OVSSwitch, failMode='standalone')

        h1 = self.addHost('h1',
                          ip='10.0.0.1/24',
                          mac='00:00:00:00:00:01')
        h2 = self.addHost('h2',
                          ip='10.0.0.2/24',
                          mac='00:00:00:00:00:02')
        h3 = self.addHost('h3',
                          ip='10.0.0.3/24',
                          mac='00:00:00:00:00:03')
        h4 = self.addHost('h4',
                          ip='10.0.0.4/24',
                          mac='00:00:00:00:00:04')

        # 每個 host 都接到 s1
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


def run():
    "建立網路，跑一個簡單測試，然後進 CLI"

    topo = FourHostOneSwitch()

    # 不使用任何 controller，完全靠 OVS 自己 learning
    net = Mininet(topo=topo,
                  controller=None,
                  autoSetMacs=False,   # 我們自己設定 MAC
                  autoStaticArp=True)  # 幫你填 ARP 表，比較好測試

    info("*** Starting network\n")
    net.start()

    info("*** Ping all hosts\n")
    net.pingAll()

    info("*** You can try: h1 ping h2, h1 ifconfig, etc.\n")
    CLI(net)   # 進入 mininet> 互動模式

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
