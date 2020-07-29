using System;
using System.Windows;
using System.IO;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System.Collections.Generic;


namespace WpfApp1
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        int j = 0;
        List<Data> data= new List<Data>();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            // Create the offline device
            OfflinePacketDevice selectedDevice = new OfflinePacketDevice(System.IO.Path.Combine(inpath.Text, "SV.pcap"));

            // Open the capture file
            using (PacketCommunicator communicator =
                    selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                                        PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                        1000))                                  // read timeout
            {
                communicator.SetFilter("ether proto 0x88ba");
                communicator.ReceivePackets(0, DispatcherHandler);
            }

            foreach (Data adata in data)
            {
                kek.Text += adata.ToString() + Environment.NewLine;
            }
        }
        // формирование массива элементов
        private void DispatcherHandler(Packet packet)
        {
            {
                data.Add(new Data()
                {
                    N = j,                                                  //счетчик пакета
                    appid = Convert.ToUInt16(packet[14].ToString("X2") + packet[15].ToString("X2")),      //APPID
                    macSrc = (packet.Ethernet.Source.ToString()),           //MAC источника
                    macDst = (packet.Ethernet.Destination.ToString())       //MAC приемника
                });
                string pak = "";
                int caseSwitch = 0;
                const int LineLength = 4;
                for (int i = 60; i != packet.Length; ++i)       //значения токов, напряжений и качества для каждого канала
                {
                    pak += (packet[i]).ToString("X2");
                    if ((i + 1) % LineLength == 0 && pak != "")
                    {
                        switch (caseSwitch)
                        {
                            case 0:
                                data[j].current1 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 1:
                                data[j].quality1 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 2:
                                data[j].current2 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 3:
                                data[j].quality2 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 4:
                                data[j].current3 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 5:
                                data[j].quality3 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 6:
                                data[j].current4 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 7:
                                data[j].quality4 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 8:
                                data[j].voltage1 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 9:
                                data[j].quality5 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 10:
                                data[j].voltage2 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 11:
                                data[j].quality6 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 12:
                                data[j].voltage3 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 13:
                                data[j].quality7 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 14:
                                data[j].voltage4 = Convert.ToInt32(pak, 16);
                                pak = "";
                                caseSwitch++;
                                break;
                            case 15:
                                data[j].quality8 = Convert.ToUInt32(pak, 16);
                                pak = "";
                                caseSwitch = 0;
                                j++;
                                break;
                        }
                    }
                }

            }      
        }
        class Data
        {
            public int N { get; set; }                //Счетчик
            public UInt16 appid { get; set; }        //APPID
            public string macSrc { get; set; }       //MAC источника
            public string macDst { get; set; }       //MAC приемника
            public Int32 current1 { get; set; }      //ток
            public Int32 current2 { get; set; }
            public Int32 current3 { get; set; }
            public Int32 current4 { get; set; }
            public Int32 voltage1 { get; set; }       //напряжение
            public Int32 voltage2 { get; set; }
            public Int32 voltage3 { get; set; }
            public Int32 voltage4 { get; set; }
            public UInt32 quality1 { get; set; }       //качество 
            public UInt32 quality2 { get; set; }
            public UInt32 quality3 { get; set; }
            public UInt32 quality4 { get; set; }
            public UInt32 quality5 { get; set; }
            public UInt32 quality6 { get; set; }
            public UInt32 quality7 { get; set; }
            public UInt32 quality8 { get; set; }
            public override string ToString()
            {
                return N + " " + appid + " " + macSrc + " " + macDst + " " + current1 + " " + quality1 + " " + current2 + " " + quality2 + " " + current3 + " " + quality3 + " " + current4 + " " + quality4 + " " +
                    voltage1 + " " + quality5 + " " + voltage2 + " " + quality6 + " " + voltage3 + " " + quality7 + " " + voltage4 + " " + quality8 + " ";
            }
        }
    }
}
