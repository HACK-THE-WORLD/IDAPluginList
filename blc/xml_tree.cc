/*
   Source for the blc IdaPro plugin
   Copyright (c) 2022 Chris Eagle

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include "xml_tree.hh"
#include "ida_minimal.hh"

//#define DEBUG_XML_TREE 1

#ifdef DEBUG_XML_TREE
#define dmsg(x, ...) msg(x, __VA_ARGS__)
#else
#define dmsg(x, ...)
#endif

#ifdef DEBUG_XML_TREE

static map<uint32_t,string> el_map;

void init_el_map() {
    el_map[11] = "addr";
    el_map[12] = "range";
    el_map[13] = "rangelist";
    el_map[14] = "register";
    el_map[15] = "seqnum";
    el_map[16] = "varnode";
    el_map[130] = "address_shift_amount";
    el_map[131] = "aggressivetrim";
    el_map[132] = "compiler_spec";
    el_map[133] = "data_space";
    el_map[134] = "default_memory_blocks";
    el_map[135] = "default_proto";
    el_map[136] = "default_symbols";
    el_map[137] = "eval_called_prototype";
    el_map[138] = "eval_current_prototype";
    el_map[139] = "experimental_rules";
    el_map[140] = "flowoverridelist";
    el_map[141] = "funcptr";
    el_map[142] = "global";
    el_map[143] = "incidentalcopy";
    el_map[144] = "inferptrbounds";
    el_map[145] = "modelalias";
    el_map[146] = "nohighptr";
    el_map[147] = "processor_spec";
    el_map[148] = "programcounter";
    el_map[149] = "properties";
    el_map[150] = "property";
    el_map[151] = "readonly";
    el_map[152] = "register_data";
    el_map[153] = "rule";
    el_map[154] = "save_state";
    el_map[155] = "segmented_address";
    el_map[156] = "spacebase";
    el_map[157] = "specextensions";
    el_map[158] = "stackpointer";
    el_map[159] = "volatile";
    el_map[102] = "bhead";
    el_map[103] = "block";
    el_map[104] = "blockedge";
    el_map[105] = "edge";
    el_map[226] = "callgraph";
    el_map[227] = "node";
    el_map[86] = "comment";
    el_map[87] = "commentdb";
    el_map[88] = "text";
    el_map[109] = "constantpool";
    el_map[110] = "cpoolrec";
    el_map[111] = "ref";
    el_map[112] = "token";
    el_map[67] = "collision";
    el_map[68] = "db";
    el_map[69] = "equatesymbol";
    el_map[71] = "facetsymbol";
    el_map[72] = "functionshell";
    el_map[73] = "hash";
    el_map[74] = "hole";
    el_map[75] = "labelsym";
    el_map[76] = "mapsym";
    el_map[77] = "parent";
    el_map[78] = "property_changepoint";
    el_map[79] = "rangeequalssymbols";
    el_map[80] = "scope";
    el_map[81] = "symbollist";
    el_map[160] = "group";
    el_map[161] = "internallist";
    el_map[162] = "killedbycall";
    el_map[163] = "likelytrash";
    el_map[164] = "localrange";
    el_map[165] = "model";
    el_map[166] = "param";
    el_map[167] = "paramrange";
    el_map[168] = "pentry";
    el_map[169] = "prototype";
    el_map[170] = "resolveprototype";
    el_map[171] = "retparam";
    el_map[172] = "returnsym";
    el_map[173] = "unaffected";
    el_map[115] = "ast";
    el_map[116] = "function";
    el_map[117] = "highlist";
    el_map[118] = "jumptablelist";
    el_map[119] = "varnodes";
    el_map[120] = "context_data";
    el_map[121] = "context_points";
    el_map[122] = "context_pointset";
    el_map[123] = "context_set";
    el_map[124] = "set";
    el_map[125] = "tracked_pointset";
    el_map[126] = "tracked_set";
    el_map[211] = "basicoverride";
    el_map[212] = "dest";
    el_map[213] = "jumptable";
    el_map[214] = "loadtable";
    el_map[215] = "normaddr";
    el_map[216] = "normhash";
    el_map[217] = "startval";
    el_map[1] = "data";
    el_map[2] = "input";
    el_map[3] = "off";
    el_map[4] = "output";
    el_map[5] = "returnaddress";
    el_map[6] = "symbol";
    el_map[7] = "target";
    el_map[8] = "val";
    el_map[9] = "value";
    el_map[10] = "void";
    el_map[270] = "XMLunknown";
    el_map[113] = "iop";
    el_map[114] = "unimpl";
    el_map[174] = "aliasblock";
    el_map[175] = "allowcontextset";
    el_map[176] = "analyzeforloops";
    el_map[177] = "commentheader";
    el_map[178] = "commentindent";
    el_map[179] = "commentinstruction";
    el_map[180] = "commentstyle";
    el_map[181] = "conventionprinting";
    el_map[182] = "currentaction";
    el_map[183] = "defaultprototype";
    el_map[184] = "errorreinterpreted";
    el_map[185] = "errortoomanyinstructions";
    el_map[186] = "errorunimplemented";
    el_map[187] = "extrapop";
    el_map[188] = "ignoreunimplemented";
    el_map[189] = "indentincrement";
    el_map[190] = "inferconstptr";
    el_map[191] = "inline";
    el_map[192] = "inplaceops";
    el_map[193] = "integerformat";
    el_map[194] = "jumpload";
    el_map[195] = "maxinstruction";
    el_map[196] = "maxlinewidth";
    el_map[197] = "namespacestrategy";
    el_map[198] = "nocastprinting";
    el_map[199] = "noreturn";
    el_map[200] = "nullprinting";
    el_map[201] = "optionslist";
    el_map[202] = "param1";
    el_map[203] = "param2";
    el_map[204] = "param3";
    el_map[205] = "protoeval";
    el_map[206] = "setaction";
    el_map[207] = "setlanguage";
    el_map[208] = "structalign";
    el_map[209] = "togglerule";
    el_map[210] = "warning";
    el_map[218] = "deadcodedelay";
    el_map[219] = "flow";
    el_map[220] = "forcegoto";
    el_map[221] = "indirectoverride";
    el_map[222] = "multistagejump";
    el_map[223] = "override";
    el_map[224] = "protooverride";
    el_map[106] = "parammeasures";
    el_map[107] = "proto";
    el_map[108] = "rank";
    el_map[89] = "addr_pcode";
    el_map[90] = "body";
    el_map[91] = "callfixup";
    el_map[92] = "callotherfixup";
    el_map[93] = "case_pcode";
    el_map[94] = "context";
    el_map[95] = "default_pcode";
    el_map[96] = "inject";
    el_map[97] = "injectdebug";
    el_map[98] = "inst";
    el_map[99] = "payload";
    el_map[100] = "pcode";
    el_map[101] = "size_pcode";
    el_map[225] = "prefersplit";
    el_map[17] = "break";
    el_map[18] = "clang_document";
    el_map[19] = "funcname";
    el_map[20] = "funcproto";
    el_map[21] = "label";
    el_map[22] = "return_type";
    el_map[23] = "statement";
    el_map[24] = "syntax";
    el_map[25] = "vardecl";
    el_map[26] = "variable";
    el_map[232] = "compiler";
    el_map[233] = "description";
    el_map[234] = "language";
    el_map[235] = "language_definitions";
    el_map[83] = "bytes";
    el_map[84] = "string";
    el_map[85] = "stringmanage";
    el_map[27] = "op";
    el_map[28] = "sleigh";
    el_map[29] = "space";
    el_map[30] = "spaceid";
    el_map[31] = "spaces";
    el_map[32] = "space_base";
    el_map[33] = "space_other";
    el_map[34] = "space_overlay";
    el_map[35] = "space_unique";
    el_map[36] = "truncate_space";
    el_map[41] = "coretypes";
    el_map[42] = "data_organization";
    el_map[43] = "def";
    el_map[47] = "entry";
    el_map[48] = "enum";
    el_map[49] = "field";
    el_map[51] = "integer_size";
    el_map[54] = "long_size";
    el_map[59] = "size_alignment_map";
    el_map[60] = "type";
    el_map[62] = "typegrp";
    el_map[63] = "typeref";
    el_map[127] = "constresolve";
    el_map[128] = "jumpassist";
    el_map[129] = "segmentop";
    el_map[82] = "high";
    el_map[228] = "localdb";
}

static map<uint32_t,string> attr_map;

void init_attr_map() {
    attr_map[27] = "first";
    attr_map[28] = "last";
    attr_map[29] = "uniq";
    attr_map[148] = "address";
    attr_map[103] = "adjustvma";
    attr_map[104] = "enable";
    attr_map[105] = "group";
    attr_map[106] = "growth";
    attr_map[107] = "key";
    attr_map[108] = "loadersymbols";
    attr_map[109] = "parent";
    attr_map[110] = "register";
    attr_map[111] = "reversejustify";
    attr_map[112] = "signext";
    attr_map[113] = "style";
    attr_map[75] = "altindex";
    attr_map[76] = "depth";
    attr_map[77] = "end";
    attr_map[78] = "opcode";
    attr_map[79] = "rev";
    attr_map[80] = "a";
    attr_map[81] = "b";
    attr_map[82] = "length";
    attr_map[83] = "tag";
    attr_map[61] = "cat";
    attr_map[62] = "field";
    attr_map[63] = "merge";
    attr_map[64] = "scopeidbyname";
    attr_map[65] = "volatile";
    attr_map[114] = "custom";
    attr_map[115] = "dotdotdot";
    attr_map[116] = "extension";
    attr_map[117] = "hasthis";
    attr_map[118] = "inline";
    attr_map[119] = "killedbycall";
    attr_map[120] = "maxsize";
    attr_map[121] = "minsize";
    attr_map[122] = "modellock";
    attr_map[123] = "noreturn";
    attr_map[124] = "pointermax";
    attr_map[125] = "separatefloat";
    attr_map[126] = "stackshift";
    attr_map[127] = "strategy";
    attr_map[128] = "thisbeforeretpointer";
    attr_map[129] = "voidlock";
    attr_map[84] = "nocode";
    attr_map[131] = "label";
    attr_map[132] = "num";
    attr_map[1] = "XMLcontent";
    attr_map[2] = "align";
    attr_map[3] = "bigendian";
    attr_map[4] = "constructor";
    attr_map[5] = "destructor";
    attr_map[6] = "extrapop";
    attr_map[7] = "format";
    attr_map[8] = "hiddenretparm";
    attr_map[9] = "id";
    attr_map[10] = "index";
    attr_map[11] = "indirectstorage";
    attr_map[12] = "metatype";
    attr_map[13] = "model";
    attr_map[14] = "name";
    attr_map[15] = "namelock";
    attr_map[16] = "offset";
    attr_map[17] = "readonly";
    attr_map[18] = "ref";
    attr_map[19] = "size";
    attr_map[20] = "space";
    attr_map[21] = "thisptr";
    attr_map[22] = "type";
    attr_map[23] = "typelock";
    attr_map[24] = "val";
    attr_map[25] = "value";
    attr_map[26] = "wordsize";
    attr_map[149] = "XMLunknown";
    attr_map[70] = "dynamic";
    attr_map[71] = "incidentalcopy";
    attr_map[72] = "inject";
    attr_map[73] = "paramshift";
    attr_map[74] = "targetop";
    attr_map[35] = "blockref";
    attr_map[36] = "close";
    attr_map[37] = "color";
    attr_map[38] = "indent";
    attr_map[39] = "off";
    attr_map[40] = "open";
    attr_map[41] = "opref";
    attr_map[42] = "varref";
    attr_map[136] = "deprecated";
    attr_map[137] = "endian";
    attr_map[138] = "processor";
    attr_map[139] = "processorspec";
    attr_map[140] = "slafile";
    attr_map[141] = "spec";
    attr_map[142] = "target";
    attr_map[143] = "variant";
    attr_map[144] = "version";
    attr_map[89] = "base";
    attr_map[90] = "deadcodedelay";
    attr_map[91] = "delay";
    attr_map[92] = "logicalsize";
    attr_map[93] = "physical";
    attr_map[94] = "piece1";
    attr_map[95] = "piece2";
    attr_map[96] = "piece3";
    attr_map[97] = "piece4";
    attr_map[98] = "piece5";
    attr_map[99] = "piece6";
    attr_map[100] = "piece7";
    attr_map[101] = "piece8";
    attr_map[102] = "piece9";
    attr_map[69] = "trunc";
    attr_map[130] = "vector_lane_sizes";
    attr_map[43] = "code";
    attr_map[44] = "contain";
    attr_map[45] = "defaultspace";
    attr_map[46] = "uniqbase";
    attr_map[47] = "alignment";
    attr_map[48] = "arraysize";
    attr_map[49] = "char";
    attr_map[50] = "core";
    attr_map[51] = "enum";
    attr_map[52] = "enumsigned";
    attr_map[53] = "enumsize";
    attr_map[54] = "intsize";
    attr_map[55] = "longsize";
    attr_map[56] = "opaquestring";
    attr_map[57] = "signed";
    attr_map[58] = "structalign";
    attr_map[59] = "utf";
    attr_map[60] = "varlength";
    attr_map[85] = "farpointer";
    attr_map[86] = "inputop";
    attr_map[87] = "outputop";
    attr_map[88] = "userop";
    attr_map[66] = "class";
    attr_map[67] = "repref";
    attr_map[68] = "symref";
    attr_map[133] = "lock";
    attr_map[134] = "main";
    attr_map[30] = "addrtied";
    attr_map[31] = "grp";
    attr_map[32] = "input";
    attr_map[33] = "persists";
    attr_map[34] = "unaff";
}

static map<uint32_t,string> specials;

static bool has_init = false;

void debug_init() {
    if (!has_init) {
        has_init = true;
        specials[0] = "stack";
        specials[1] = "join";
        specials[2] = "fspec";
        specials[3] = "iop";
        init_el_map();
        init_attr_map();
    }
}

static uint32_t indent = 0;

#endif


XmlElement::~XmlElement() {
    for (XmlList::iterator i = children.begin(); i != children.end(); i++) {
        delete *i;
    }
    for (vector<XmlAttribute*>::iterator i = attributes.begin(); i != attributes.end(); i++) {
        delete *i;
    }
}

static const string empty("");

const string &XmlElement::getContent() {
    for (vector<XmlAttribute*>::iterator i = attributes.begin(); i != attributes.end(); i++) {
        if ((*i)->id == attrib_content) {
            return (*i)->getContent();
        }
    }
    return empty;
}

uint64_t get_int(istream &f, uint32_t l) {
    uint64_t r = 0;
    uint8_t b;
    for (uint32_t i = 0; i < l; i++) {
        r <<= 7;
        f >> b;
        if (b & 0x80) {
            r += b & 0x7f;
        }
        else {
            dmsg("Expected high bit of int byte to be set: 0x%02x\n", b);
            return r;
        }
    }
    return r;
}

XmlElement *parse(XmlElement *parent, istream &f) {
    uint64_t v;
    XmlElement *self = NULL;
    while (1) {
        uint8_t b;
        f >> b;
        if (f.eof()) {
            break;
        }
        uint8_t tag = b & 0xC0;
        uint32_t iiiii = b & 0x1f;
        uint8_t next = b & 0x20;
        if (next) {
            uint8_t b2;
            f >> b2;
            if (f.eof()) {
                dmsg("Unexpected EOF attempting to read b2\n");
                break;
            }
            if (b2 & 0x80) {
                iiiii = (iiiii << 7) + (b2 & 0x7f);
            }
            else {
                dmsg("Expected high bit of b2 to be set: 0x%02x\n", b2);
                break;
            }
        }
        if (tag == 0x40) {
#ifdef DEBUG_XML_TREE
            dmsg("%*sElement start: %s 0x%x (%d)\n", indent, "", el_map[iiiii].c_str(), iiiii, iiiii);
            indent += 4;
#endif
            self = new XmlElement(iiiii);
            parse(self, f);
            if (self->tag == ast_tag_break) {
                delete self;
                self = NULL;
            } else if (self->tag == ast_tag_syntax && self->attributes.size() == 1 && (self->attributes[0]->content == "" || self->attributes[0]->content == " ")) {
                delete self;
                self = NULL;
            } else if (parent) {
                parent->addChild(self);
            }
        }
        else if (tag == 0x80) {
#ifdef DEBUG_XML_TREE
            indent -= 4;
            dmsg("%*sElement end: %s 0x%x (%d), with %u children, and %u attributes\n", indent, "", el_map[iiiii].c_str(), iiiii, iiiii, parent->children.size(), parent->attributes.size());
#endif
            if (iiiii != parent->tag) {
                dmsg("ERROR: Unbalanced element tags: 0x%x (%d), expected 0x%x (%d)\n", iiiii, iiiii, parent->tag, parent->tag);
            }
            return self;
        }
        else if (tag == 0xC0) {
#ifdef DEBUG_XML_TREE
            dmsg("%*sAttr start: %s 0x%x (%d)\n", indent, "", attr_map[iiiii].c_str(), iiiii, iiiii);
#endif
            uint8_t attr;
            f >> attr;
            if (f.eof()) {
                dmsg("Unexpected EOF attempting to read attr\n");
                break;
            }
            uint8_t tttt = (attr >> 4) & 0xf;
            uint8_t llll = attr & 0xf;
            switch (tttt) {
            case 1:  //boolean
#ifdef DEBUG_XML_TREE
                dmsg("%*s    boolean: %d\n", indent, "", llll);
#endif
                parent->addAttribute(new XmlAttribute(iiiii, tttt, llll));
                break;
            case 2: // positive signed
                v = get_int(f, llll);
#ifdef DEBUG_XML_TREE
                dmsg("%*s    Positive signed: 0x%x (%d)\n", indent, "", v, v);
#endif
                parent->addAttribute(new XmlAttribute(iiiii, tttt, v));
                break;
            case 3: // negative signed
                v = get_int(f, llll);
#ifdef DEBUG_XML_TREE
                dmsg("%*s    Negative signed: -0x%x (-%d)\n", indent, "", v, v);
#endif
                parent->addAttribute(new XmlAttribute(iiiii, tttt, v));
                break;
            case 4: // unsigned
                v = get_int(f, llll);
#ifdef DEBUG_XML_TREE
                dmsg("%*s    Unsigned: 0x%x (%d)\n", indent, "", v, v);
#endif
                parent->addAttribute(new XmlAttribute(iiiii, tttt, v));
                break;
            case 5: // basic address space
                v = get_int(f, llll);
#ifdef DEBUG_XML_TREE
                dmsg("%*s    Basic address space: 0x%x (%d)\n", indent, "", v, v);
#endif
                parent->addAttribute(new XmlAttribute(iiiii, tttt, v));
                break;
            case 6: // special address space
#ifdef DEBUG_XML_TREE
                dmsg("%*s    Special address space: %s\n", indent, "", specials[llll].c_str());
#endif
                parent->addAttribute(new XmlAttribute(iiiii, tttt, llll));
                break;
            case 7: { // string
                v = get_int(f, llll);
                char *s = new char[v + 1];
                f.read(s, v);
                s[v] = 0;
#ifdef DEBUG_XML_TREE
                dmsg("%*s    String length: 0x%x (%d)\n", indent, "", v, v);
                dmsg("%*s    String content: '%s'\n", indent, "", s);
#endif
                parent->addAttribute(new XmlAttribute(iiiii, tttt, s));
                delete [] s;
                break;
            }
            default:
                dmsg("Unexpected attr type 0x%x (%d)\n", tttt, tttt);
                break;
            }
        }
        else {
            dmsg("Unexpected start byte: 0x%02x\n", b);
        }
    }
    return self;
}

XmlElement *build_from_packed(istream &ifs) {
#ifdef DEBUG_XML_TREE
    debug_init();
#endif
    XmlElement *root = parse(NULL, ifs);
    return root;
}

void dump_tree(XmlElement *node, uint32_t indent) {
#ifdef DEBUG_XML_TREE
    dmsg("%*sELEM %s:%u\n", indent, "", el_map[node->tag].c_str(), node->tag);
    for (vector<XmlAttribute*>::iterator i = node->attributes.begin(); i != node->attributes.end(); i++) {
        uint32_t id = (*i)->id;
        dmsg("%*sATTR %s:%u: ", indent + 4, "", attr_map[id].c_str(), id);
        if (id == attrib_content) {
            dmsg("'%s'\n", (*i)->content.c_str());
        } else {
            dmsg("0x%lx (%lu)\n", (*i)->val, (*i)->val);
        }
    }
    for (XmlList::iterator i = node->children.begin(); i != node->children.end(); i++) {
        dump_tree(*i, indent + 4);
    }
#endif
}

