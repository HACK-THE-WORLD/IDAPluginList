import ida_kernwin

import codecs

g_icon_data_ascii = (
    b"89504E470D0A1A0A0000000D4948445200000020000000200806000000737A7A",
    b"F4000000097048597300000EC300000EC301C76FA8640000001974455874536F",
    b"667477617265007777772E696E6B73636170652E6F72679BEE3C1A0000036249",
    b"4441545885ADD75B8855651407F0DF346383948E4E99A6537445C2ACB1521421",
    b"8C28822E4418965009094120E5180411F6D08588EE3E48D4832464045D686648",
    b"7CA8888AB2FBE5A507C12CA8C0ACD46CB2C6D3C3FA367BCF696F3DFB9C59B0F9",
    b"F6FEBE75F99FF5ADDBE9D23A0D602596E242CC443FFEC66FD8830FF012BEAAA1",
    b"F798342F29FD178D169F2D3871328C2FC1DE1A868BCF9B9D1A9F8BDFDB349E3D",
    b"577402E0E50E8D37C4B53D86EEBAC64FC3F8240028C6442D5A5FA26417BE3C06",
    b"B083F844F9D52DAF03604B41700C3715CEE6E379917E19CFCFB81733124F8F70",
    b"7D11C0737500BC5310BCA782670EAEC2A5985AC1F35A41CFBB75007C2877696F",
    b"1DC1269A2FBFB28FCA188EAB109C92D68F85ABDBA5EFF04D7A3FBE0E802C6D0E",
    b"75603CA3EF8F66AB0AC091B4362601C0585ABB5A057032CE994400998DD3714A",
    b"2B006E431FD6E2AFC2FE62916AEB705689DC3CDC29B26659617F0CB78BE6B4B6",
    b"15C40FCB03EF82B43E28326214EFE3808975FE32FC2ADAF128FEC043E96C615A",
    b"776173B3B19E1200E305005F8BFE3F844B44BEF7E1228CE0C7C437171B318CF3",
    b"71173E171D7167C15655CC4DA021118459FEAFC7F6F43E9C404C15F171BFB896",
    b"46DA1BC6B4C4FB7A3A2302700C8F341B2B43B42F09CC4EDF7BC5FD4EC17471BF",
    b"0309E4E6F4FC9378FA7071921FC0FEA4E3A4F4837E6AC10196A55F7475FA9E25",
    b"EEF7C96464A1A86A6F604DF2C2567C2A0275061E17635A7FD27165D2B9A21500",
    b"BD497844EECE4562CE6BE030B661016EC5202EC78BF2B2FB993C134E10B17048",
    b"8D316D8D70EB6E137BC1EC02A89B45BD5881D5696FBA6852197589401EC78656",
    b"8D67B45AFC9A2515E7AB44F40F094F94D182A4E3962A23474B8BED497851C579",
    b"2FCE104DE617B9678AB434ADEFB503601FBEC07515E7BBC5FD9F2BAEE64009CF",
    b"35F856DE906AD31D62B01C6CDA9F8967B1438C696F95F09C2DE2E8EE768D1311",
    b"FC83706137CEC3D3C2E547F0365EC09FC9D856DC20826F5454CA8EFFA05C2F62",
    b"E1A9F43D881B4577CB681AAE4DBC3D22301B26CE921DD1A6A470A38ABE5EA075",
    b"C23BB586D02ACAC6A86EE1DE065EC59925BCA7E295C4B34D3E55B53553F68BC6",
    b"B15FDE13BA44313928AAE1081EC53322080FA7B30D722FCD12F1F1447A6F8956",
    b"8A529C8DD38B9BCEE7E001D10FF68806B303F78969AA4859216A8834FD5F46FC",
    b"0777AA1B71191AD8320000000049454E44AE426082",
)
g_icon_data = codecs.decode(b"".join(g_icon_data_ascii), 'hex')

class icon_handler(object):
    def __init__(self, icon_data, hexify=False):
        if hexify:
            icon_data = self.ascii_to_hex(icon_data)
        self.icon_data = icon_data
        
    @staticmethod
    def ascii_to_hex(icon_data_ascii):
        return codecs.decode(b"".join(icon_data_ascii), 'hex')
    
    @staticmethod
    def icon_bg_change(icon_data, bg_change=False, bin_transform=False):
        try:
            from PyQt5 import QtCore
            from PyQt5 import QtWidgets
            from PyQt5 import QtGui
        except ImportError:
            return None
        
        icon_image = QtGui.QImage()
        icon_image.loadFromData(icon_data, 'PNG')
        icon_pixmap = QtGui.QPixmap(icon_image)

        if bg_change:
            image = QtGui.QImage(icon_image.size(), QtGui.QImage.Format_ARGB32)
            image.fill(QtCore.Qt.transparent)
            p = QtGui.QPainter()
            p.begin(image)
            p.setOpacity(0.7)
            p.setBrush(QtCore.Qt.white)
            p.setPen(QtCore.Qt.white)
            p.drawRect(QtCore.QRect(0, 0, image.size().width()-1, image.size().height()-1))
            p.setOpacity(1.0)
            p.drawPixmap(0, 0, icon_pixmap)
            p.end()
            pixmap = QtGui.QPixmap(image)
        else:
            image = icon_image
            pixmap = icon_pixmap
        
        if bin_transform:
            byte_array = QtCore.QByteArray()
            buffer = QtCore.QBuffer(byte_array)
            buffer.open(QtCore.QIODevice.WriteOnly)
            image.save(buffer, 'PNG')
            return buffer.data().data()
        return pixmap

    @staticmethod
    def change_widget_icon(w, icon_data, bg_change=False, max_try=100):
        if w is None:
            return False
            
        if icon_data is None:
            return False
        
        try:
            import sip
            from PyQt5 import QtCore
            from PyQt5 import QtWidgets
            from PyQt5 import QtGui
        except ImportError:
            return False
        
        pixmap = icon_handler.icon_bg_change(icon_data, bg_change)
        if pixmap:
            icon = QtGui.QIcon(pixmap)
            
            # find the widget
            widget = sip.wrapinstance(int(w), QtWidgets.QWidget)
            find_flag = False
            i = 0
            while i < max_try and widget and type(widget) != QtWidgets.QMainWindow:
                if type(widget) == QtWidgets.QWidget:
                    find_flag = True
                    break
                widget = widget.parent()
                i += 1
            
            if not find_flag:
                return False
            widget.setWindowIcon(icon)
        else:
            return False
        return True
    
    def change_widget_icon_w(self, icon_data=None, bg_change=False, w=None):
        if icon_data is None:
            icon_data = self.icon_data
        return self._change_widget_icon(w, icon_data, bg_change)

    def register_icon(self, data=None, img_format="png"):
        if data is None:
            data = self.icon_data
        return ida_kernwin.load_custom_icon(data=data, format=img_format)

