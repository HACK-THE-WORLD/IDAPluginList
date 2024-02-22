/*
   Source for the blc IdaPro plugin
   Copyright (c) 2019 Chris Eagle

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

#include <stdint.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <string>

#include "xml_tree.hh"
#include "ast.hh"
#include "ida_minimal.hh"
#include "plugin.hh"

using std::map;
using std::set;
using std::string;

//#define DEBUG_AST 1

#ifdef DEBUG_AST
#define dmsg(x, ...) msg(x, __VA_ARGS__)
#else
#define dmsg(x, ...)
#endif

enum op_keywords_t {
    kw_null,
    kw_if,
    kw_switch,
    kw_while,
    kw_return,
    kw_assign
};

enum color_tag_t {
    keyword_color = 0,		///< Keyword in the high-level language
    comment_color = 1,		///< Comments
    type_color = 2,		///< Data-type identifiers
    funcname_color = 3,		///< Function identifiers
    var_color = 4,		///< Local variable identifiers
    const_color = 5,		///< Constant values
    param_color = 6,		///< Function parameters
    global_color = 7,		///< Global variable identifiers
    no_color = 8,		///< Un-highlighted
    error_color = 9,		///< Indicates a warning or error state
    special_color = 10		///< A token with special/highlighted meaning
};

static const string WHILE("while");
static const string DO("do");
static const string IF("if");
static const string ELSE("else");
static const string BREAK("break");
static const string DEFAULT("default");
static const string SWITCH("switch");
static const string CASE("case");
static const string GOTO("goto");
static const string RETURN("return");

static const string LBRACE("{");
static const string RBRACE("}");
static const string LPAREN("(");
static const string RPAREN(")");
static const string LBRACKET("[");
static const string RBRACKET("]");
static const string COLON(":");
static const string SEMICOLON(";");
static const string COMMA(",");

enum g_token {
    g_null,
    g_lbrace,
    g_rbrace,
    g_lparen,
    g_rparen,
    g_cond_close,
    g_lbracket,
    g_rbracket,
    g_and,
    g_xor,
    g_or,
    g_not,
    g_bnot,
    g_logical_and,
    g_logical_or,
    g_comma,
    g_semi,
    g_lshift,
    g_rshift,
    g_lt,
    g_lte,
    g_gt,
    g_gte,
    g_assign,
    g_eq,
    g_ne,
    g_plus,
    g_minus,
    g_mod,
    g_div,
    g_star,
    g_plus_eq,
    g_minus_eq,
    g_star_eq,
    g_div_eq,
    g_mod_eq,
    g_and_eq,
    g_or_eq,
    g_xor_eq,
    g_lshift_eq,
    g_rshift_eq,
    g_plusplus,
    g_minusminus,
    g_qmark,
    g_colon,

    g_break,
    g_keyword,
    g_var,
    g_funcname,
    g_const,
    g_type,
    g_eol_cmt,
    g_cmt_open,
    g_cmt_close,
    g_label,
    g_symbol,
    g_op
};

static map<uint32_t,string> tag_map;
static map<string,g_token> ops;
static set<string> binary_ops;
static set<string> unary_ops;
static map<string,op_keywords_t> op_map;
static set<string> reserved;
static map<string,string> type_map;

static const string empty_string("");

typedef vector<XmlElement *> XmlList;		///< A list of XML elements

static void block_handler(XmlElement *el, Block *block);
//static Statement *inner_block(XmlElement *child);
static VarDecl *vardecl_handler(XmlElement *el);
static Statement *statement_handler(XmlElement *el);
static Expression *expr_handler(XmlList::iterator &it, XmlList::iterator &end, bool comma_ok = true);
static Switch *switch_handler(XmlList::iterator &it);
static Else *else_handler(XmlList::iterator &it);
static DoWhile *do_handler(XmlList::iterator &it);

static const string &getAttributeContent(XmlElement *el, uint32_t id) {
    size_t nattr = el->attributes.size();

    for (size_t i = 0; i < nattr; i++) {
        if (el->attributes[i]->id == id) {
            return el->attributes[i]->content;
        }
    }
    return empty_string;
}

static uint64_t getAttributeValue(XmlElement *el, uint32_t id) {
    size_t nattr = el->attributes.size();

    for (size_t i = 0; i < nattr; i++) {
        if (el->attributes[i]->id == id) {
            return el->attributes[i]->val;
        }
    }
    return 0;
}

// in some cases Ghidra uses <funcname> and others <op>, in all cases
// color="funcname" will be present
bool is_funcname_color(XmlElement *el) {
    return getAttributeValue(el, attrib_color) == funcname_color;
}

bool is_keyword_color(XmlElement *el) {
    return getAttributeValue(el, attrib_color) == keyword_color;
}

bool is_const_color(XmlElement *el) {
    return getAttributeValue(el, attrib_color) == const_color;
}

bool is_global_color(XmlElement *el) {
    return getAttributeValue(el, attrib_color) == global_color;
}

void escape_string(const string &str, string &escaped) {
    for (string::const_iterator i = str.cbegin(); i != str.cend(); i++) {
        switch (*i) {
            case '\n':
                escaped += "\\n";
                break;
            case '\t':
                escaped += "\\t";
                break;
            case '\\':
                escaped += "\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            default:
                if (*i < 0x20 || *i == 0x7f) {
                    char buf[16];
                    snprintf(buf, sizeof(buf), "\\x%02x", *i & 0xff);
                    escaped += buf;
                }
                else{
                    escaped.push_back(*i);
                }
                break;
        }
    }
}

static XmlElement *find_child(XmlElement *el, uint32_t tag) {
    XmlList &children = el->getChildren();
    for (XmlList::iterator it = children.begin(); it != children.end(); it++) {
        XmlElement *child = *it;
        if (child->tag == tag) {
            return child;
        }
    }
    return NULL;
}

static XmlElement *get_child(XmlList::iterator &it) {
    XmlElement *child = *it;
    dmsg("Processing %u/%s\n", child->tag, child->getContent().c_str());
    return child;
}

const char *debug_print(AstItem *exp) {
    string l = exp->line;
    exp->line.clear();
    exp->do_print();
    string r = exp->line;
    exp->line = l;
    return tag_remove(r.c_str());
}

AstItem::AstItem() : no_indent(false), no_semi(false), line_begin(1),
                     line_end(1), col_start(-1), col_end(-1),
                     color(COLOR_DEFAULT) {};

vector<string> *AstItem::cfunc;
string AstItem::line;
size_t AstItem::indent;
size_t AstItem::line_index;

void AstItem::flush(bool no_indent) {
    string spaces;
    if (!no_indent) {
        spaces.append(indent, ' ');
    }
    if (cfunc) {
        cfunc->push_back(spaces + line);
    }
//    dmsg("append: %s\n", cfunc->back().c_str());
    line.clear();
    line_index = 0;
}

void AstItem::append(char ch, bool count) {
    line.push_back(ch);
    line_index += count ? 1 : 0;
}

void AstItem::color_on(char tag) {
    append(COLOR_ON, false);
    append(tag, false);
}

void AstItem::color_off(char tag) {
    append(COLOR_OFF, false);
    append(tag, false);
}

void AstItem::append(const char *v) {
    append(string(v));
}

void AstItem::append(const string &v) {
    line.append(v);
    line_index += v.length();
}

void AstItem::append_colored(char tag, const char *v) {
    append_colored(tag, string(v));
}

void AstItem::append_colored(char tag, const string &v) {
    color_on(tag);
    append(v);
    color_off(tag);
}

void AstItem::print_in() {
    if (cfunc) {
        line_begin = cfunc->size();
        col_start = line_index;
    }
}

void AstItem::print_out() {
    if (cfunc) {
        line_end = cfunc->size();
        col_end = line_index;
    }
}

void AstItem::do_print() {
    print_in();
    print();
    print_out();
}

void brace_print(AstItem &item, bool final_append = true) {
    AstItem::append_colored(COLOR_SYMBOL, LBRACE);
    AstItem::flush();
    AstItem::indent += 3;
    item.do_print();
    AstItem::indent -= 3;
    AstItem::append_colored(COLOR_SYMBOL, RBRACE);
    if (final_append) {
        AstItem::flush();
    }
}

void Statement::print() {
    line += "<statement>";
}

void Type::print() {
    print("");
}

void Type::print(const string &var) {
    bool need_space = true;
    print_in();
    if (is_const) {
        append_colored(COLOR_KEYWORD, "const ");
    }
    append_colored(COLOR_KEYWORD, name);
    if (ptr) {
        if (!is_cast) {
            append(' ');
        }
        color_on(COLOR_SYMBOL);
        line.append(ptr, '*');
        line_index += ptr;
        color_off(COLOR_SYMBOL);
        need_space = false;
    }
    if (var.length() > 0) {
        if (need_space) {
            append(' ');
        }
        append_colored(COLOR_DNAME, var);
    }
    for (vector<uint32_t>::iterator i = dims.begin(); i != dims.end(); i++) {
        append_colored(COLOR_SYMBOL, LBRACKET);
        if (*i) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%u", *i);
            append_colored(COLOR_NUMBER, buf);
        }
        append_colored(COLOR_SYMBOL, RBRACKET);
    }
    print_out();
}

void Type::rename(const string &oldname, const string &newname) {
    if (oldname == name) {
        name = newname;
    }
}

void Expression::print() {
    append("<expr>");
}

void LiteralExpr::print() {
    append(val);
}

NameExpr::NameExpr(const string &var, bool _global) : name(var), global(_global) {
    adjust_thunk_name(name);
}

void NameExpr::print() {
    if (is_extern(name)) {
        append_colored(COLOR_IMPNAME, name);
    }
    else {
        append_colored(COLOR_DNAME, name);
    }
}

void NameExpr::rename(const string &oldname, const string &newname) {
//    dmsg("NameExpr::rename %s from %s to %s\n", name.c_str(), oldname.c_str(), newname.c_str());
    if (oldname == name) {
        name = newname;
    }
}

void FuncNameExpr::print() {
    if (is_extern(name)) {
        append_colored(COLOR_IMPNAME, name);
    }
    else if (is_library_func(name)) {
        append_colored(COLOR_DEFAULT, name);
    }
    else {
        append_colored(COLOR_DEFAULT, name);
    }
}

void FuncNameExpr::rename(const string &oldname, const string &newname) {
    if (oldname == name) {
        name = newname;
    }
}

void LabelExpr::print() {
    append(label);
}

void LabelExpr::rename(const string &oldname, const string &newname) {
    if (oldname == label) {
        label = newname;
    }
}

void LabelStatement::print() {
    line += label;
    append_colored(COLOR_SYMBOL, COLON);
}

void LabelStatement::rename(const string &oldname, const string &newname) {
    if (oldname == label) {
        label = newname;
    }
}

void GotoStatement::print() {
    append_colored(COLOR_KEYWORD, GOTO);
    append(' ');
    label->do_print();
}

void GotoStatement::rename(const string &oldname, const string &newname) {
    label->rename(oldname, newname);
}

void BreakStatement::print() {
    append_colored(COLOR_KEYWORD, BREAK);
}

ExprStatement::~ExprStatement() {
    delete expr;
}

void ExprStatement::print() {
    expr->do_print();
}

void ExprStatement::rename(const string &oldname, const string &newname) {
    expr->rename(oldname, newname);
}

CommaExpr::~CommaExpr() {
    delete lhs;
    delete rhs;
}

void CommaExpr::print() {
    lhs->do_print();
    append_colored(COLOR_SYMBOL, COMMA);
    append(' ');
    rhs->do_print();
}

void CommaExpr::rename(const string &oldname, const string &newname) {
    lhs->rename(oldname, newname);
    rhs->rename(oldname, newname);
}

void BinaryExpr::print() {
    lhs->do_print();
    append(' ');
    append_colored(COLOR_SYMBOL, op);
    append(' ');
    rhs->do_print();
}

void BinaryExpr::rename(const string &oldname, const string &newname) {
    lhs->rename(oldname, newname);
    rhs->rename(oldname, newname);
}

void UnaryExpr::print() {
    append_colored(COLOR_SYMBOL, op);
    expr->do_print();
}

void UnaryExpr::rename(const string &oldname, const string &newname) {
    expr->rename(oldname, newname);
}

CastExpr::CastExpr(const string &typ) {
    type = new Type(typ);
    type->is_cast = true;
}

CastExpr::~CastExpr() {
    delete type;
}

void CastExpr::print() {
    type->do_print();
}

void CastExpr::rename(const string &oldname, const string &newname) {
    type->rename(oldname, newname);
}

void TypeCast::print() {
    type->do_print();
    expr->do_print();
}

void TypeCast::rename(const string &oldname, const string &newname) {
    type->rename(oldname, newname);
    expr->rename(oldname, newname);
}

void IntegerLiteral::print() {
    append(val);
}

uint64_t IntegerLiteral::get_value() {
    return strtoull(val.c_str(), NULL, 0);
}

void StringLiteral::print() {
    append_colored(COLOR_DSTR, "\"");
    string escaped;
    escape_string(val, escaped);
    append_colored(COLOR_DSTR, escaped);
    append_colored(COLOR_DSTR, "\"");
}

void CharExpr::print() {
    append_colored(COLOR_SYMBOL, "'");
    append(val);
    append_colored(COLOR_SYMBOL, "'");
}

void ParenExpr::print() {
    append_colored(COLOR_SYMBOL, LPAREN);
    if (inner) {
        inner->do_print();
    }
    append_colored(COLOR_SYMBOL, RPAREN);
}

void ParenExpr::rename(const string &oldname, const string &newname) {
    if (inner) {
//        dmsg("ParenExpr::rename from %s to %s\n", oldname.c_str(), newname.c_str());
        inner->rename(oldname, newname);
    }
}

void ArrayExpr::print() {
    array->do_print();
    append_colored(COLOR_SYMBOL, LBRACKET);
    index->do_print();
    append_colored(COLOR_SYMBOL, RBRACKET);
}

void ArrayExpr::rename(const string &oldname, const string &newname) {
    array->rename(oldname, newname);
    index->rename(oldname, newname);
}

void Block::print() {
    for (vector<Statement*>::iterator i = block.begin(); i != block.end(); i++) {
        Statement *s = *i;
        if (s) {
            s->do_print();
        }
        else {
            dmsg("Attempting to print a NULL Statement\n");
        }
        if (!s->no_semi) {
            append_colored(COLOR_SYMBOL, SEMICOLON);
        }
        flush(s->no_indent);
    }
}

Block::~Block() {
    for (vector<Statement*>::iterator i = block.begin(); i != block.end(); i++) {
        delete *i;
    }
}

void Block::rename(const string &oldname, const string &newname) {
    for (vector<Statement*>::iterator i = block.begin(); i != block.end(); i++) {
        Statement *s = *i;
        if (s) {
//            dmsg("Block::rename from %s to %s\n", oldname.c_str(), newname.c_str());
            s->rename(oldname, newname);
        }
    }
}

void VarDecl::print() {
    type->print(var->name);
}

const string &VarDecl::getName() {
    Expression *expr = var;
    while (true) {
        NameExpr *n = dynamic_cast<NameExpr*>(expr);
        if (n) {
            return n->name;
        }
        UnaryExpr *u = dynamic_cast<UnaryExpr*>(expr);
        if (u) {
            expr = u->expr;
            continue;
        }
        ParenExpr *p = dynamic_cast<ParenExpr*>(expr);
        if (p) {
            expr = p->inner;
            continue;
        }
        ArrayExpr *a = dynamic_cast<ArrayExpr*>(expr);
        if (a) {
            expr = a->array;
            continue;
        }
        dmsg("VarDecl unexpected expr type\n");
        return empty_string;
    }
}

void VarDecl::rename(const string &oldname, const string &newname) {
    type->rename(oldname, newname);
    var->rename(oldname, newname);
    if (init) {
        init->rename(oldname, newname);
    }
}

VarDecl::~VarDecl() {
    delete type;
    delete var;
    delete init;
}

void Funcproto::print() {
    return_type->do_print();
    for (vector<string>::iterator i = keywords.begin(); i != keywords.end(); i++) {
        append(' ');
        append(*i);
    }
    append(' ');
    append(name);
    append_colored(COLOR_SYMBOL, LPAREN);
    for (vector<VarDecl*>::iterator i = parameters.begin(); i != parameters.end(); i++) {
        if (i != parameters.begin()) {
            append_colored(COLOR_SYMBOL, COMMA);
            append(' ');
        }
        (*i)->do_print();
    }
    append_colored(COLOR_SYMBOL, RPAREN);
}

void Funcproto::rename(const string &oldname, const string &newname) {
    return_type->rename(oldname, newname);
    if (oldname == name) {
        name = newname;
    }
    for (vector<VarDecl*>::iterator i = parameters.begin(); i != parameters.end(); i++) {
        (*i)->rename(oldname, newname);
    }
}

Funcproto::~Funcproto() {
    delete return_type;
    for (vector<VarDecl*>::iterator i = parameters.begin(); i != parameters.end(); i++) {
        delete *i;
    }
}

CallExpr::~CallExpr() {
    delete func;
    delete args;
}

void CallExpr::print() {
    func->do_print();
    args->do_print();
}

void CallExpr::rename(const string &oldname, const string &newname) {
//    dmsg("CallExpr::rename from %s to %s\n", oldname.c_str(), newname.c_str());
    func->rename(oldname, newname);
    args->rename(oldname, newname);
}

void Else::print() {
    append_colored(COLOR_KEYWORD, ELSE);
    append(' ');
    brace_print(block, false);
}

void Else::rename(const string &oldname, const string &newname) {
    block.rename(oldname, newname);
}

void If::print() {
    append_colored(COLOR_KEYWORD, IF);
    append(' ');
    append_colored(COLOR_SYMBOL, LPAREN);
    cond->do_print();
    append_colored(COLOR_SYMBOL, RPAREN);
    append(' ');
    brace_print(block, _else != NULL);
    if (_else) {
        _else->do_print();
    }
}

void If::rename(const string &oldname, const string &newname) {
    ConditionalStatement::rename(oldname, newname);
    if (_else) {
        _else->rename(oldname, newname);
    }
}

void ConditionalStatement::rename(const string &oldname, const string &newname) {
//    dmsg("ConditionalStatement::rename from %s to %s\n", oldname.c_str(), newname.c_str());
    cond->rename(oldname, newname);
    block.rename(oldname, newname);
}

void While::print() {
    append_colored(COLOR_KEYWORD, WHILE);
    append(' ');
    append_colored(COLOR_SYMBOL, LPAREN);
    cond->do_print();
    append_colored(COLOR_SYMBOL, RPAREN);
    append(' ');
    brace_print(block, false);
}

void DoWhile::print() {
    append_colored(COLOR_KEYWORD, DO);
    append(' ');
    brace_print(block, false);
    append(' ');
    append_colored(COLOR_KEYWORD, WHILE);
    append(' ');
    append_colored(COLOR_SYMBOL, LPAREN);
    cond->do_print();
    append_colored(COLOR_SYMBOL, RPAREN);
}

void Case::print() {
    if (is_default) {
        append_colored(COLOR_KEYWORD, DEFAULT);
    }
    else {
        append_colored(COLOR_KEYWORD, CASE);
        append(' ');
        append(label);
    }
    append_colored(COLOR_SYMBOL, COLON);
    flush();
    indent += 3;
    Block::print();
    indent -= 3;
}

void Switch::print() {
    append_colored(COLOR_KEYWORD, SWITCH);
    append(' ');
    append_colored(COLOR_SYMBOL, LPAREN);
    cond->do_print();
    append_colored(COLOR_SYMBOL, RPAREN);
    append(' ');
    append_colored(COLOR_SYMBOL, LBRACE);
    flush();
    indent += 3;
    for (vector<Case*>::iterator i = cases.begin(); i != cases.end(); i++) {
        (*i)->do_print();
    }
    indent -= 3;
    append_colored(COLOR_SYMBOL, "}");
}

void Switch::rename(const string &oldname, const string &newname) {
    cond->rename(oldname, newname);
    for (vector<Case*>::iterator i = cases.begin(); i != cases.end(); i++) {
        (*i)->rename(oldname, newname);
    }
}

void Return::print() {
    append_colored(COLOR_KEYWORD, RETURN);
    if (expr) {
        append(' ');
        expr->do_print();
    }
}

void Return::rename(const string &oldname, const string &newname) {
    if (expr) {
        expr->rename(oldname, newname);
    }
}

AssignExpr::~AssignExpr() {
    delete lval;
    delete rval;
}

void AssignExpr::print() {
    lval->do_print();
    append(' ');
    append_colored(COLOR_SYMBOL, "=");
    append(' ');
    rval->do_print();
}

void AssignExpr::rename(const string &oldname, const string &newname) {
//    dmsg("AssignExpr::rename from %s to %s\n", oldname.c_str(), newname.c_str());
    lval->rename(oldname, newname);
    rval->rename(oldname, newname);
}

void Ternary::print() {
    expr->do_print();
    append(' ');
    append_colored(COLOR_SYMBOL, "?");
    append(' ');
    _true->do_print();
    append(' ');
    append_colored(COLOR_SYMBOL, COLON);
    append(' ');
    _false->do_print();
}

void Ternary::rename(const string &oldname, const string &newname) {
    expr->rename(oldname, newname);
    _true->rename(oldname, newname);
    _false->rename(oldname, newname);
}

void Function::print() {
    prototype.do_print();
    flush();
    brace_print(block);
}

void Function::print(vector<string> *cfunc) {
    line_index = 0;
    AstItem::cfunc = cfunc;
    line.clear();
    indent = 0;

    do_print();

    line_index = 0;
    AstItem::cfunc = NULL;
    line.clear();
    indent = 0;
}

void Function::rename(const string &oldname, const string &newname) {
    prototype.rename(oldname, newname);
    block.rename(oldname, newname);
}

XmlList::iterator find_match(XmlList::iterator &it, const string &sym, uint64_t open) {
    XmlList::iterator res = it;
    while ((*res)->getContent() != sym || getAttributeValue(*res, attrib_close) != open) {
        res++;
    }
    return res;
}

XmlList::iterator find(XmlList::iterator &it, const string &sym) {
    XmlList::iterator res = it;
    while ((*res)->getContent() != sym) {
        res++;
    }
    return res;
}

static bool is_const_expr(Expression *e, uint64_t *val) {
    IntegerLiteral *num = dynamic_cast<IntegerLiteral*>(e);
    if (num) {
        *val = num->get_value();
        dmsg("Found const expression (a) %s\n", num->val.c_str());
        return true;
    }
    NameExpr *ne = dynamic_cast<NameExpr*>(e);
    if (ne) {
        char *endptr;
        const char *s = ne->name.c_str();
        *val = strtoull(s, &endptr, 0);
        if (endptr != s && *endptr == 0) {
            //name was a valid integer literal
            dmsg("Found const expression (b) %s\n", s);
            return true;
        }
        //not an int so see if name refers to const data
        uint64_t addr;
        if (ne->global && address_of(ne->name, &addr) && is_read_only(addr)) {
            dmsg("Found const expression (d) %s\n", ne->name.c_str());
            if (get_value(addr, val)) {
                return true;
            }
        }
        return false;
    }
    UnaryExpr *ue = dynamic_cast<UnaryExpr*>(e);
    if (ue) {
        if (is_const_expr(ue->expr, val)) {
            uint64_t old = *val;
            if (ue->op == "-") {
                *val = 0 - *val;
            }
            else if (ue->op == "~") {
                *val = ~*val;
            }
            else if (ue->op == "!") {
                *val = !*val;
            }
            else {
                return false;
            }
            dmsg("Found const expression (c) %s0x%lx\n", ue->op.c_str(), old);
            return true;
        }
    }
    return false;
}

static Expression *simplify_const(uint64_t cval) {
    dmsg("simplify_const for 0x%lx\n", cval);
    string val;
    if (is_function_start(cval)) {
        get_name(val, cval, 0);
        return new FuncNameExpr(val);
    }
    if (get_string(cval, val)) {
        dmsg("simplify_const became a string: %s\n", val.c_str());
        return new StringLiteral(val);
    }
    if (is_named_addr(cval, val)) {
        return new UnaryExpr("&", new NameExpr(val));
    }
    return NULL;
}

const string &map_type(const string &type_name) {
    if (type_map.find(type_name) != type_map.end()) {
        return type_map[type_name];
    }
    return type_name;
}

static Type *type_handler(XmlElement *el) {
    //map the type name here
    const string &type_name = el->getContent();
    return new Type(map_type(type_name));
}

static Return *return_handler(XmlList::iterator &it, XmlList::iterator &end) {
    Return *result = new Return();
    Expression *expr = expr_handler(it, end);
    EmptyExpr *ee = dynamic_cast<EmptyExpr*>(expr);
    if (ee) {
        delete ee;
        result->expr = NULL;
    }
    else {
        result->expr = expr;
    }
    return result;
}

static Statement *statement_handler(XmlElement *el) {
    static int scount = 0;
    dmsg("statement_handler in %d\n", scount++);
    Statement *result = NULL;
    Expression *lhs = NULL;
    XmlList &children = el->getChildren();
    XmlList::iterator end = children.end();
    for (XmlList::iterator it = children.begin(); it < end; it++) {
        XmlElement *child = get_child(it);
        if (is_keyword_color(child) && child->getContent() == BREAK) {
            return new BreakStatement();
        }
        switch (child->tag) {
            case ast_tag_op: {
                //need to consume consecutive children at this level to form a statement
                switch (op_map[child->getContent()]) {
                    case kw_return:
                        result = return_handler(++it, end);
                        dmsg("statement_handler out(1) %d\n", --scount);
                        return result;
                    default:
                        dmsg("no op_map match for '%s' in statement\n", child->getContent().c_str());
                        lhs = expr_handler(it, end);
                        dmsg("no op_map match for '%s' in statement result: %s\n", child->getContent().c_str(), debug_print(lhs));
                        if (result) {
                            dmsg("oddly, result is '%s'\n", debug_print(result));
                        }
                        break;
                }
                break;
            }
            case ast_tag_label:
                result = new LabelStatement(child->getContent());
                dmsg("statement_handler out(2) %d - Label: %s\n", --scount, debug_print(result));
                return result;
            case ast_tag_syntax: {
                if (child->getContent() == GOTO) {
                    GotoStatement *g = new GotoStatement();
                    g->label = expr_handler(++it, end);
                    dmsg("statement_handler out(3) %d\n", --scount);
                    return g;
                }
                else {
                    dmsg("no syntax match for '%s' in statement\n", child->getContent().c_str());
                    dmsg("Trying to build an expression\n");
                    Expression *expr = expr_handler(it, end);
                    if (expr) {
                       dmsg("statement_handler out(4) %d\n", --scount);
                        return new ExprStatement(expr);
                    }
                }
                break;
            }
            default:
                dmsg("no tag_map match for %s (%u) in statement, trying expression\n", tag_map[child->tag].c_str(), child->tag);
                lhs = expr_handler(it, end);
                break;
        }
    }
    if (result == NULL) {
        dmsg("statement_handler is returning NULL\n");
        if (lhs != NULL) {
            result = new ExprStatement(lhs);
        }
        else {
            dmsg("statement_handler has no result\n");
        }
    }
    else {
        dmsg("returning from statement_handler -> %p\n", result);

    }
    dmsg("statement_handler out(0) %d - %s\n", --scount, debug_print(result));
    return result;
}

static VarDecl *vardecl_handler(XmlElement *el) {
    bool in_dim = false;
    XmlList &children = el->getChildren();
    VarDecl *result = new VarDecl();
    XmlList::iterator it;
    XmlList::iterator end = children.end();
    for (it = children.begin(); result->init == NULL && it < end; it++) {
        XmlElement *child = get_child(it);
        const string &content = child->getContent();
        switch (child->tag) {
            case ast_tag_type:
                result->type = type_handler(child);
                break;
            case ast_tag_op:
                if (content == "*" && result->type) {
                    result->type->ptr++;
                }
                else if (content == "=") {
                    result->init = expr_handler(++it, end);
                }
                break;
            case ast_tag_variable:
                result->var = new NameExpr(content);
                break;
            case ast_tag_syntax: {
                if (content == "[") {
                    in_dim = true;
                }
                else if (content == "]") {
                    in_dim = false;
                }
                else if (in_dim && is_const_color(child) && result->type) {
                    result->type->dims.push_back(strtoul(content.c_str(), NULL, 0));
                }
                break;
            }
            default:
                break;
        }
    }
    return result;
}

static void funcproto_handler(XmlElement *el, Function *f) {
    bool have_proto = false;
    bool have_name = false;
    XmlList &children = el->getChildren();
    for (XmlList::iterator it = children.begin(); it < children.end(); it++) {
        XmlElement *child = get_child(it);
        if (have_proto && !have_name && is_keyword_color(child)) {
            f->prototype.keywords.push_back(child->getContent());
            continue;
        }
        switch (child->tag) {
            case ast_tag_return_type: {
                f->prototype.return_type = type_handler(find_child(child, ast_tag_type));
                XmlList &rchildren = child->getChildren();
                for (XmlList::iterator cit = rchildren.begin(); cit != rchildren.end(); cit++) {
                    XmlElement *e = *cit;
                    if (e->tag == ast_tag_op && e->getContent() == "*") {
                        f->prototype.return_type->ptr++;
                    }
                }
                have_proto = true;
                break;
            }
            case ast_tag_syntax:
                break;
            case ast_tag_vardecl: {
                VarDecl *d = vardecl_handler(child);
                if (d) {
                    f->prototype.parameters.push_back(d);
                }
                else {
                   //error
                }
                break;
            }
            case ast_tag_funcname:
                f->prototype.name = child->getContent();
                have_name = true;
                break;
            default:
                break;
        }
    }
}

static CastExpr *cast_handler(XmlList::iterator &it, XmlList::iterator &end) {
    dmsg("Entering cast_handler\n");
    XmlElement *child = get_child(it);
    const string &type_name = child->getContent();
    CastExpr *result = new CastExpr(map_type(type_name));  //map type name change here
    while (++it < end) {
        child = get_child(it);
        const string &content = child->getContent();
        if (child->tag == ast_tag_op) {
            if (content == "*") {
                result->type->ptr++;
            }
            else {
                dmsg("cast_handler unknown op: %s\n", content.c_str());
            }
        }
        else if (child->tag == ast_tag_syntax) {
            if (content == RPAREN) {
                dmsg("Leaving cast_handler (1) - %p\n", result);
                it--;
                return result;
            }
            else {
                dmsg("cast_handler unknown syntax: %s\n", content.c_str());
            }
        }
        else {
            dmsg("cast_handler unknown tag: %s (%d)\n", tag_map[child->tag].c_str(), child->tag);
        }
    }
    dmsg("Leaving cast_handler (2) - %p\n", result);
    return result;
}

Expression *make_name(const string &name, bool global) {
    //add checks to see if name is a const, then convert to the const
    //or whether name is a static string, then convert to quoted string
    return new NameExpr(name, global);
}

Expression *make_variable(XmlElement *var) {
    Expression *result = NULL;
    const string &text = var->getContent();

    //add checks to see if name is a const, then convert to the const
    //or whether name is a static string, then convert to quoted string

    if (is_const_color(var)) {
        char *end;
        uint64_t val = strtoull(text.c_str(), &end, 0);
        if (*end == 0) {
            dmsg("numeric literal: %s\n", text.c_str());
            result = new IntegerLiteral(text);
            Expression *e = simplify_const(val);
            if (e) {
                delete result;
                result = e;
            }
        }
        else {
            dmsg("other literal: %s\n", text.c_str());
            result = new LiteralExpr(text);
        }
    }
    else if (is_global_color(var)) {
        uint64_t addr;
        if (address_of(text, &addr) && is_read_only(addr) && !is_function_start(addr)) {
            //try to dereference this?
            dmsg("const global: %s\n", text.c_str());
            result = make_name(text, true);
        }
        else {
            result = make_name(text, true);
        }
    }
    else {
        result = make_name(text, false);
    }
    return result;
}

static Expression *make_unary(const string &op, XmlList::iterator &it, XmlList::iterator &end) {
    UnaryExpr *u = new UnaryExpr(op, expr_handler(it, end, false));
    if (op == "*") {
        NameExpr *n = dynamic_cast<NameExpr*>(u->expr);
        if (n) {
            dmsg("made unary expr: %s%s\n", op.c_str(), n->name.c_str());
            string new_name;
            if (simplify_deref(n->name, new_name)) {
                Expression *expr = make_name(new_name, n->global);
                delete u;
                return expr;
            }
        }
    }
    else if (op == "&") {
        NameExpr *n = dynamic_cast<NameExpr*>(u->expr);
        if (n) {
            dmsg("made unary expr: %s%s\n", op.c_str(), n->name.c_str());
            string strval;
            if (get_string(n->name.c_str(), strval)) {
                dmsg("make_unary became a string: %s\n", strval.c_str());
                delete u;
                return new StringLiteral(strval);
            }
        }
    }
    return u;
}

static Expression *make_binary(const string &op, Expression *lhs, XmlList::iterator &it, XmlList::iterator &end) {
    uint64_t v1;
    uint64_t v2;
    BinaryExpr *b = new BinaryExpr(op, lhs, expr_handler(it, end, false));
    if (op == "+") {
        if (is_const_expr(b->lhs, &v1) && is_const_expr(b->rhs, &v2)) {
            Expression *e = simplify_const(v1 + v2);
            if (e) {
                delete b;
                return e;
            }
        }
    }
    else if (op == "-") {
        if (is_const_expr(b->lhs, &v1) && is_const_expr(b->rhs, &v2)) {
            Expression *e = simplify_const(v1 - v2);
            if (e) {
                delete b;
                return e;
            }
        }
    }
    return b;
}

static Expression *expr_handler(XmlList::iterator &it, XmlList::iterator &end, bool comma_ok) {
    static int ecount = 0;
    Expression *result = NULL;
    uint64_t open = 0;
    ParenExpr *p = NULL;
    dmsg("expr_handler in %d\n", ecount++);
    for (; it < end; it++) {
        XmlElement *child = get_child(it);
        const string &content = child->getContent();
        if (is_funcname_color(child)) {
            dmsg("expr_handler op building CallExpr(1)\n");
            CallExpr *call = new CallExpr(new FuncNameExpr(content), expr_handler(++it, end));

            dmsg("expr_handler op built CallExpr - %s\n", debug_print(call));
            dmsg("expr_handler out(3) %d\n", --ecount);
            return call;
        }
        switch (child->tag) {
            case ast_tag_variable:
                result = make_variable(child);
                break;
            case ast_tag_type: {
                CastExpr *cast = cast_handler(it, end);
                result = cast;
                dmsg("expr_handler out(1) %d\n", --ecount);
                return result;
            }
            case ast_tag_label:
                result = new LabelExpr(content);
                dmsg("expr_handler out(2) %d\n", --ecount);
                return result;
            case ast_tag_funcname: {
                dmsg("expr_handler tag building CallExpr(2)\n");
                CallExpr *call = new CallExpr(new FuncNameExpr(content), expr_handler(++it, end));

                dmsg("expr_handler tag built CallExpr - %s\n", debug_print(call));
                dmsg("expr_handler out(3) %d\n", --ecount);
                return call;
            }
            case ast_tag_statement: {
                dmsg("expr_handler tag building statement\n");
                Statement *s = statement_handler(child);
                ExprStatement *e = dynamic_cast<ExprStatement*>(s);
                if (e) {
                    //take ownership of the sub-expression;
                    result = e->expr;
                    e->expr = NULL;
                    delete e;
                }
                else {
                    dmsg("Expected ExprStatement but didn't get one\n");
                    delete s;
                }
            }
            case ast_tag_syntax: {
                if (is_const_color(child)) {
                    dmsg("expr_handler syntax building LiteralExpr for %s\n", content.c_str());
                    result = new LiteralExpr(content);
                    dmsg("   %s\n", debug_print(result));
                }
                else if (unary_ops.find(content) != unary_ops.end() && result == NULL) {
                    dmsg("expr_handler syntax building UnaryExpr for %s\n", content.c_str());
                    //result = new UnaryExpr(content, expr_handler(++it, end));
                    result = make_unary(content, ++it, end);
                    dmsg("   %s\n", debug_print(result));
                }
                else if (binary_ops.find(content) != binary_ops.end() && result != NULL) {
                    dmsg("expr_handler syntax building BinaryExpr for %s\n", content.c_str());
                    result = make_binary(content, result, ++it, end);
 //                   result = new BinaryExpr(content, result, expr_handler(++it, end));
                    dmsg("   %s\n", debug_print(result));
                }
                else {
                    switch (ops[content]) {
                        case g_null:
                            dmsg("expr_handler syntax op is g_null for '%s'\n", content.c_str());
                            if (content.length() > 0) {
                                char *end;
                                uint64_t val = strtoull(content.c_str(), &end, 0);
                                if (*end == 0) {
                                    result = new IntegerLiteral(content);
                                }
                                else {
                                    result = new LiteralExpr(content);
                                }
                            }
                            break;
                        case g_lparen: {
                            //recurse into expr, we now have a parenthized expression
                            open = getAttributeValue(child, attrib_open);
                            dmsg("expr_handler syntax building ParenExpr for %lu\n", open);
                            p = new ParenExpr(expr_handler(++it, end, true));
                            it++; //increment past the close )
                            dmsg("   ParenExpr(%lu): %s\n", open, debug_print(p));
                            CastExpr *c = dynamic_cast<CastExpr*>(p->inner);
                            if (c) {
                                result = new TypeCast(p, expr_handler(++it, end));
                                dmsg("   TypeCast(%lu): %s\n", open, debug_print(result));
                            }
                            else {
                                if (result != NULL) {
                                    //This looks more like a fucntion call then
                                    //test special case for function name
                                    ParenExpr *rp = dynamic_cast<ParenExpr*>(result);
                                    if (rp) {
                                        NameExpr *rn = dynamic_cast<NameExpr*>(rp->inner);
                                        if (rn) {
                                            Expression *ne = make_name(rn->name, rn->global);
                                            delete rp;
                                            result = ne;
                                        }
                                    }
                                    result = new CallExpr(result, p);
                                    dmsg("   Looks like function call: %s\n", debug_print(result));
                                }
                                else {
                                    result = p;
                                }
                            }
                            break;
                        }
                        case g_rparen: {
                            uint64_t close = getAttributeValue(child, attrib_close);
                            dmsg("expr_handler rolling back rparen at level %d\n", ecount - 1);
                            it--;

                            dmsg("expr_handler terminating on rparen %lu\n", close);
                            dmsg("expr_handler out(5) %d - %p - %s\n", --ecount, result, typeid(result).name());
                            return result;
                        }
                        case g_lbracket: {
                            //recurse into expr, we now have a parenthized expression
                            Expression *index = expr_handler(++it, end);
                            result = new ArrayExpr(result, index);
                            break;
                        }
                        case g_rbracket: {
                            // this is probably unmatched, so return what we have to caller
                            dmsg("expr_handler terminating on rbracket\n");
                            uint64_t close = getAttributeValue(child, attrib_close);
                            dmsg("expr_handler out(6) %d - %p\n", --ecount, result);
                            return result;
                        }
                        case g_comma: { //never get here ??
                            Expression *rhs = expr_handler(++it, end);
                            result = new CommaExpr(result, rhs);
                            dmsg("expr_handler comma out(7) %d - %p\n", --ecount, result);
                            return result;
                        }
                        case g_semi: {
                            dmsg("expr_handler terminating on semicolon\n");
                            dmsg("expr_handler out(8) %d - %p\n", --ecount, result);
                            return result;
                        }
                        case g_assign: {
                            dmsg("expr_handler terminating on assign\n");
                            dmsg("expr_handler out(9) %d - %p\n", --ecount, result);
                            return result;
                        }
                    }
                }
                break;
            }
            case ast_tag_op: {
               if (unary_ops.find(content) != unary_ops.end() && result == NULL) {
                  dmsg("expr_handler op building UnaryExpr\n");
                  //result = new UnaryExpr(op, expr_handler(++it, end));
                  result = make_unary(content, ++it, end);
                  dmsg("expr_handler op built UnaryExpr(%p) for %s\n", result, content.c_str());
                  dmsg("   %s\n", debug_print(result));
               }
               else if (binary_ops.find(content) != binary_ops.end() && result != NULL) {
                  dmsg("expr_handler op building BinaryExpr\n");
                  result = make_binary(content, result, ++it, end);
 //                 result = new BinaryExpr(content, result, expr_handler(++it, end));
                  dmsg("expr_handler op building BinaryExpr(%p) for %s\n", result, content.c_str());
                  dmsg("   %s\n", debug_print(result));
                  //dmsg("expr_handler out %d(10) - %p\n", --ecount, result);
                  //return result;
               }
               else {
                  switch (ops[content]) {
                     case g_null:
                        dmsg("expr_handler op op is g_null\n");
                        break;
                     case g_assign: {
                        dmsg("expr_handler op building AssignExpr\n");
                        Expression *rhs = expr_handler(++it, end);
                        result = new AssignExpr(result, rhs);
                        dmsg("expr_handler op built AssignExpr(%p) - %s\n", result, debug_print(result));
                        dmsg("expr_handler out(11) %d\n", --ecount);
                        return result;
                     }
                     case g_comma: {  //comma always shows up as an op?
                        if (comma_ok) {
                           Expression *rhs = expr_handler(++it, end);
                           result = new CommaExpr(result, rhs);
                           dmsg("expr_handler out(12) %d\n", --ecount);
                        }
                        else {
                           it--;
                           dmsg("expr_handler out(12.5) %d\n", --ecount);
                        }
                        return result;
                     }
                     default:
                        dmsg("expr_handler no case for op/%s\n", content.c_str());
                        break;
                  }
               }
               break;
            }
            default:
                dmsg("expr_handler unhandled tag_map: %s/%u(%s)\n", tag_map[child->tag].c_str(), child->tag, content.c_str());
               break;
        }
        //it can be advanced in some of the functions called above
        if (it == end) {
           break;
        }
    }

    dmsg("expr_handler out(side loop) %d - %p\n", --ecount, result);
    if (result == NULL) {
        return new EmptyExpr();
    }
    else {
        dmsg("   returning: %s\n", debug_print(result));
    }
    return result;
}

static void conditional_common(ConditionalStatement *cs, XmlList::iterator &it) {
    XmlElement *child;

    it = find(it, LPAREN);
    uint64_t open = getAttributeValue(*it, attrib_open);
    it++;

    XmlList::iterator end = find_match(it, RPAREN, open);

    cs->cond = expr_handler(it, end);

    it = ++end;  //resume after condition's close paren

    child = get_child(it);
    while (child->tag != ast_tag_block && child->tag != ast_tag_statement) {
        it++;
        child = get_child(it);
    }
    if (child->tag == ast_tag_block) {
        block_handler(child, &cs->block);
    }
    else { //statement
        cs->block.push_back(statement_handler(child));
    }
}

static If *if_handler(XmlList::iterator &it) {
    If *result = new If();
    dmsg("building new if\n");

    conditional_common(result, it);

    //don't try to handle else here
    //check for else in main handler

    return result;
}

static While *while_handler(XmlList::iterator &it, XmlList::iterator &end) {
    static int wcount = 0;
    While *result = new While();
    dmsg("building new while - %d\n", wcount++);

    //ghidra in its infinite wisdom does not place the body of
    //a while inside of a <block> tag, but MAYBE, a block enclose
    //everything from 'while(...) {...}'

    it = find(it, LPAREN);
    uint64_t open = getAttributeValue(*it, attrib_open);
    it++;

    XmlList::iterator cend = find_match(it, RPAREN, open);

    result->cond = expr_handler(it, cend);

    it = ++cend;  //resume after condition's close paren

    //let's hope they at least brace everything
    it = find(it, LBRACE);
    it++;

    //this is basically the same as a block_handler loop
    //without the benefit of knowing where the end of the child
    //list is
    while (it < end) {
        //we're not inside a block so we don't have a defined end
        //point for child iteration
        XmlElement *child = get_child(it);
        const string &content = child->getContent();
        if (content == "}") {
            //this is the only way to know we've reached the end at this level?
            break;
        }

        switch (child->tag) {
            case ast_tag_label: {
                LabelStatement *label = new LabelStatement(content);
                result->push_back(label);
                break;
            }
            case ast_tag_block: {
                dmsg("while_handler::block\n");
                block_handler(child, &result->block);
                break;
            }
            case ast_tag_op: { //this will be a compound statement??
                dmsg("while_handler::op\n");
                //need to consume consecutive children at this level to form a statement
                switch (op_map[content]) {
                    case kw_if: {
                        dmsg("while_handler::kw_if\n");
                        If *_if = if_handler(++it);
                        if (_if) {
                            result->push_back(_if);
                        }
                        else {
                        }
                        break;
                    }
                    case kw_switch: {
                        dmsg("while_handler::kw_switch\n");
                        Switch *sw = switch_handler(++it);
                        if (sw) {
                            result->push_back(sw);
                        }
                        else {
                        }
                        break;
                    }
                    case kw_while: {
                        //I hope this can never happend without first being in a nested <block>
                        //otherwise the end iterator being passed in below will be the end of the
                        //outer while, not the inner while we are about to parse.
                        dmsg("while_handler::kw_while\n");
                        While *w = while_handler(++it, end);
                        if (w) {
                            result->push_back(w);
                        }
                        else {
                        }
                        break;
                    }
                    case kw_return:
 //                       block->block.push_back(return_handler(it));
                        break;
                    default:
                        dmsg("while_handler no op_map match for %s\n", content.c_str());
                        break;
                }
                break;
            }
            case ast_tag_statement: {
                dmsg("while_handler::statement\n");
                Statement *s = statement_handler(child);
                if (s) {
                    result->push_back(s);
                }
                else {
                    //error
                }
                break;
            }
            case ast_tag_syntax:
                if (child->getContent() == ELSE) {
                    If *_if = dynamic_cast<If*>(result->back());
                    if (_if) {
                        dmsg("while_handler appending else to previous if\n");
                        Else *_else = else_handler(it);
                        if (_else) {
                            _if->_else = _else;
                        }
                        else {
                        }
                    }
                    else {
                        //error, we don't have an if statement to pair with the else
                        dmsg("Seeing else, bu previous is %s\n", typeid(result->back()).name());
                    }
                }
                else if (content == DO) {
                    dmsg("while_handler::statement\n");
                    Statement *s = do_handler(it);
                    if (s) {
                        result->push_back(s);
                    }
                    else {
                        //error
                    }
                }
                break;
            default:
                break;
        }
        it++;
    }
    dmsg("while_handler out %d\n", --wcount);
    return result;
}

static Case *build_case(XmlList::iterator &it, bool is_default = false) {
    Case *result = new Case(is_default);

    if (!is_default) {
        while (!is_const_color(*it)) {
            it++;
        }
        result->label = (*it)->getContent();
        dmsg("case label is %s\n", result->label.c_str());

        it++;
    }
    XmlElement *child = get_child(it);
    while (child->tag != ast_tag_block && child->tag != ast_tag_statement) {
        it++;
        child = get_child(it);
    }
    if (child->tag == ast_tag_block) {
        block_handler(child, result);
    }
    else { //statement
        result->block.push_back(statement_handler(child));
    }
//    it++;

    return result;
}

static Switch *switch_handler(XmlList::iterator &it) {
    Switch *result = new Switch();
    XmlElement *child;
    dmsg("building new switch\n");

    it = find(it, LPAREN);
    uint64_t open = getAttributeValue(*it, attrib_open);
    it++;

    XmlList::iterator end = find_match(it, RPAREN, open);

    result->cond = expr_handler(it, end);

    it = ++end;  //resume after condition's close paren

    while (true) {
        child = get_child(it);
        const string &content = child->getContent();
        if (content == "}") {
            break;
        }
        else if (content == CASE) {
            result->cases.push_back(build_case(it));
        }
        else if (content == DEFAULT) {
            result->cases.push_back(build_case(it, true));
            result->cases.back()->is_default = true;
        }
        else {
            dmsg("switch loop, skipping %s\n", child->getContent().c_str());
        }
        it++;
    }
    return result;
}

static DoWhile *do_handler(XmlList::iterator &it) {
    DoWhile *result = new DoWhile();
    XmlElement *child;
    dmsg("building new do/while\n");

    child = get_child(it);
    while (child->tag != ast_tag_block && child->tag != ast_tag_statement) {
        it++;
        child = get_child(it);
    }
    if (child->tag == ast_tag_block) {
        block_handler(child, &result->block);
    }
    else { //statement
        result->block.push_back(statement_handler(child));
    }

    //find the condition
    while (true) {
        child = get_child(it);
        if (child->getContent() == LPAREN) {
            break;
        }
        it++;
    }
    uint64_t open = getAttributeValue(child, attrib_open);
    it++;

    XmlList::iterator end = find_match(it, RPAREN, open);

    result->cond = expr_handler(it, end);

    it = ++end;  //resume after condition's close paren

    return result;
}

static Else *else_handler(XmlList::iterator &it) {
    XmlElement *child = get_child(it);
    Else *result = new Else();
    while (child->tag != ast_tag_block && child->tag != ast_tag_statement) {
        it++;
        child = get_child(it);
    }
    if (child->tag == ast_tag_block) {
        block_handler(child, &result->block);
    }
    else { //statement
        result->block.push_back(statement_handler(child));
    }
    dmsg("built an else - %p\n", result);
    return result;
}

static void block_handler(XmlElement *el, Block *block) {
    static int bcount = 0;
    dmsg("block_handler in %d\n", bcount++);
    XmlList &children = el->getChildren();
    XmlList::iterator it = children.begin();
    XmlList::iterator end = children.end();
    while (it < end) {
        XmlElement *child = get_child(it);
        const string &content = child->getContent();
        switch (child->tag) {
            case ast_tag_label: {
                LabelStatement *label = new LabelStatement(content);
                block->push_back(label);
                break;
            }
            case ast_tag_block: {
                dmsg("block_handler::block\n");
                block_handler(child, block);
                break;
            }
            case ast_tag_op: { //this will be a compound statement??
                dmsg("block_handler::op\n");
                //need to consume consecutive children at this level to form a statement
                switch (op_map[content]) {
                    case kw_if: {
                        dmsg("block_handler::kw_if\n");
                        If *_if = if_handler(++it);
                        if (_if) {
                            block->push_back(_if);
                        }
                        else {
                        }
                        break;
                    }
                    case kw_switch: {
                        dmsg("block_handler::kw_switch\n");
                        Switch *sw = switch_handler(++it);
                        if (sw) {
                            block->push_back(sw);
                        }
                        else {
                        }
                        break;
                    }
                    case kw_while: {
                        dmsg("block_handler::kw_while\n");
                        While *w = while_handler(++it, end);
                        if (w) {
                            block->push_back(w);
                        }
                        else {
                        }
                        break;
                    }
                    case kw_return:
 //                       block->block.push_back(return_handler(it));
                        break;
                    default:
                        dmsg("no op_map match for %s\n", content.c_str());
                        break;
                }
                break;
            }
            case ast_tag_statement: {
                dmsg("block_handler::statement\n");
                Statement *s = statement_handler(child);
                if (s) {
                    block->push_back(s);
                }
                else {
                    //error
                }
                break;
            }
            case ast_tag_syntax:
                if (content == ELSE) {
                    If *_if = dynamic_cast<If*>(block->back());
                    if (_if) {
                        dmsg("appending else to previous if\n");
                        Else *_else = else_handler(it);
                        if (_else) {
                            _if->_else = _else;
                        }
                        else {
                        }
                    }
                    else {
                        //error, we don't have an if statement to pair with the else
                        dmsg("Seeing else, bu previous is %s\n", typeid(block->back()).name());
                    }
                }
                else if (content == DO) {
                    dmsg("block_handler::statement\n");
                    Statement *s = do_handler(it);
                    if (s) {
                        block->push_back(s);
                    }
                    else {
                        //error
                    }
                }
                break;
            default:
                break;
         }
/*
         //it can be advance in some of the functions called above
         if (it == end) {
             break;
         }
*/
         it++;
    }
    dmsg("block_handler out %d\n", --bcount);
}

void init_maps(void) {
    static bool maps_are_init = false;
    if (!maps_are_init) {
        maps_are_init = true;

        tag_map[ast_tag_syntax] = "syntax";
        tag_map[ast_tag_break] = "break";
        tag_map[ast_tag_funcproto] = "funcproto";
        tag_map[ast_tag_vardecl] = "vardecl";
        tag_map[ast_tag_return_type] = "return_type";
        tag_map[ast_tag_type] = "type";
        tag_map[ast_tag_variable] = "variable";
        tag_map[ast_tag_block] = "block";
        tag_map[ast_tag_statement] = "statement";
        tag_map[ast_tag_funcname] = "funcname";
        tag_map[ast_tag_op] = "op";
        tag_map[ast_tag_label] = "label";

        op_map[IF] = kw_if;
        op_map[SWITCH] = kw_switch;
        op_map[WHILE] = kw_while;
        op_map[RETURN] = kw_return;
        op_map["="] = kw_assign;

        ops[LBRACE] = g_lbrace;
        ops[RBRACE] = g_rbrace;
        ops[LPAREN] = g_lparen;
        ops[RPAREN] = g_rparen;
        ops[LBRACKET] = g_lbracket;
        ops[RBRACKET] = g_rbracket;
        ops["&"] = g_and;
        ops["|"] = g_or;
        ops["^"] = g_xor;
        ops["!"] = g_not;
        ops["~"] = g_bnot;
        ops["||"] = g_logical_or;
        ops["&&"] = g_logical_and;
        ops[COMMA] = g_comma;
        ops[SEMICOLON] = g_semi;
        ops["<<"] = g_lshift;
        ops[">>"] = g_rshift;
        ops["<"] = g_lt;
        ops["<="] = g_lte;
        ops[">"] = g_gt;
        ops[">="] = g_gte;
        ops["="] = g_assign;
        ops["=="] = g_eq;
        ops["!="] = g_ne;
        ops["+"] = g_plus;
        ops["-"] = g_minus;
        ops["%"] = g_mod;
        ops["/"] = g_div;
        ops["*"] = g_star;
        ops["+="] = g_plus_eq;
        ops["-="] = g_minus_eq;
        ops["*="] = g_star_eq;
        ops["/="] = g_div_eq;
        ops["%="] = g_mod_eq;
        ops["&="] = g_and_eq;
        ops["|="] = g_or_eq;
        ops["^="] = g_xor_eq;
        ops["<<="] = g_lshift_eq;
        ops[">>="] = g_rshift_eq;
        ops["++"] = g_plusplus;
        ops["--"] = g_minusminus;
        ops["?"] = g_qmark;
        ops[COLON] = g_colon;

        binary_ops.insert("&");
        binary_ops.insert("|");
        binary_ops.insert("^");
        binary_ops.insert("||");
        binary_ops.insert("&&");
        binary_ops.insert("<<");
        binary_ops.insert(">>");
        binary_ops.insert("<");
        binary_ops.insert("<=");
        binary_ops.insert(">");
        binary_ops.insert(">=");
        binary_ops.insert("==");
        binary_ops.insert("!=");
        binary_ops.insert("+");
        binary_ops.insert("-");
        binary_ops.insert("%");
        binary_ops.insert("/");
        binary_ops.insert("*");

        unary_ops.insert("++");
        unary_ops.insert("--");
        unary_ops.insert("++ ");
        unary_ops.insert("-- ");
        unary_ops.insert("-");
        unary_ops.insert("!");
        unary_ops.insert("~");
        unary_ops.insert("*");
        unary_ops.insert("&");

        reserved.insert(WHILE);
        reserved.insert(DO);
        reserved.insert(IF);
        reserved.insert(ELSE);
        reserved.insert(BREAK);
        reserved.insert(DEFAULT);
        reserved.insert(SWITCH);
        reserved.insert(CASE);
        reserved.insert(GOTO);
        reserved.insert(RETURN);
        reserved.insert("for");

        reserved.insert("int");
        reserved.insert("bool");
        reserved.insert("char");
        reserved.insert("short");
        reserved.insert("long");
        reserved.insert("signed");
        reserved.insert("unsigned");
        reserved.insert("float");
        reserved.insert("double");
        reserved.insert("void");
        reserved.insert("NULL");

        reserved.insert("uint8_t");
        reserved.insert("uint16_t");
        reserved.insert("uint32_t");
        reserved.insert("uint64_t");
        reserved.insert("int8_t");
        reserved.insert("int16_t");
        reserved.insert("int32_t");
        reserved.insert("int64_t");

        type_map["uint1"] = "uint8_t";
        type_map["uint2"] = "uint16_t";
        type_map["uint4"] = "uint32_t";
        type_map["uint8"] = "uint64_t";
        type_map["int1"] = "int8_t";
        type_map["int2"] = "int16_t";
        type_map["int4"] = "int32_t";
        type_map["int8"] = "int64_t";
        type_map["float4"] = "float";
        type_map["float8"] = "double";
        type_map["xunknown1"] = "__uint8";
        type_map["xunknown2"] = "__uint16";
        type_map["xunknown4"] = "__uint32";
        type_map["xunknown8"] = "__uint64";
    }
}

bool is_reserved(const string &word) {
    return reserved.find(word) != reserved.end();
}

Function *func_from_tree(XmlElement *func, uint64_t addr) {
    init_maps();
    int num_decls = 0;
    int num_blocks = 0;
    if (func->tag != ast_tag_function) {
        return NULL;
    }
    Function *result = new Function(addr);
    bool have_proto = false;
    XmlList &children = func->getChildren();
    for (XmlList::iterator it = children.begin(); it < children.end(); it++) {
        XmlElement *child = get_child(it);
        if (!have_proto && child->tag != ast_tag_funcproto) {
            continue;
        }
        have_proto = true;
        switch (child->tag) {
            case ast_tag_funcproto:
                funcproto_handler(child, result);
                break;
            case ast_tag_syntax:
                break;
            case ast_tag_vardecl: {
                Statement *s = vardecl_handler(child);
                if (s) {
                    result->block.push_back(s);
                    num_decls++;
                }
                else {
                    //error
                }
                break;
            }
            case ast_tag_block:
                if (num_decls && !num_blocks) {
                    result->block.push_back(new EmptyStatement());
                }
                block_handler(child, &result->block);
                num_blocks++;
                break;
            default:
                break;
        }
    }
    return result;
}

VarDecl *find_decl(Function *ast, const string &sword) {
    vector<Statement*> &bk = ast->block.block;
    vector<VarDecl*> &parms = ast->prototype.parameters;

    //Scan function parameters
    for (vector<VarDecl*>::iterator i = parms.begin(); i != parms.end(); i++) {
        VarDecl *decl = *i;
        if (decl->var->name == sword) {
            return decl;
        }
    }

    //Scan locals
    for (vector<Statement*>::iterator i = bk.begin(); i != bk.end(); i++) {
        VarDecl *decl = dynamic_cast<VarDecl*>(*i);
        if (decl) {
            if (decl->var->name == sword) {
                return decl;
            }
        }
        else {
            break;
        }
    }

    return NULL;
}

VarDecl *find_decl(Function *ast, int col, int line) {
    vector<Statement*> &bk = ast->block.block;
    vector<VarDecl*> &parms = ast->prototype.parameters;

    //Scan function parameters
    for (vector<VarDecl*>::iterator i = parms.begin(); i != parms.end(); i++) {
        VarDecl *decl = *i;
        if (decl->col_start <= col && decl->col_end > col && decl->line_begin == line && decl->line_end == line) {
            return decl;
        }
    }

    //Scan locals
    for (vector<Statement*>::iterator i = bk.begin(); i != bk.end(); i++) {
        VarDecl *decl = dynamic_cast<VarDecl*>(*i);
        if (decl) {
            if (decl->col_start <= col && decl->col_end > col && decl->line_begin == line && decl->line_end == line) {
               return decl;
            }
        }
        else {
            break;
        }
    }

    return NULL;
}

