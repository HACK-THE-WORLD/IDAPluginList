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

#ifndef __BLC_AST_H
#define __BLC_AST_H

#include <string>
#include <vector>

namespace ghidra {

    class Element;

}

using std::string;
using std::vector;

using ghidra::Element;

//A very crude AST for representing Ghidra generated
//decompilations

//we make no attempt to validate the structure of the tree
//assuming instead that Ghidra feeds us a syntacitically correct
//result. This simplifies things like ensuring the left side
//of an assignment is an lval, which we just assume ghidra has
//enforced

struct AstItem {

   static vector<string> *cfunc;
   static string line;
   static size_t indent;
   static void flush(bool no_indent = false);
   static void append(char ch, bool count = true);
   static void append(const char *v);
   static void append(const string &v);
   static void append_colored(char tag, const char *v);
   static void append_colored(char tag, const string &v);
   static void color_on(char tag);
   static void color_off(char tag);

   //index into line discounting color codes
   static size_t line_index;

   int line_begin;
   int line_end;
   int col_start;
   int col_end;
   char color;
   bool no_indent;
   bool no_semi;

   AstItem();

   void print_in();
   void print_out();

   void do_print();

   virtual void print() = 0;

   virtual void rename(const string &oldname, const string &newname) {}
};

struct Statement : public AstItem {
   virtual ~Statement() {};
   virtual void print();
};

struct Type : public AstItem {
   vector<uint32_t> dims;
   string name;
   uint32_t ptr;
   bool is_const;
   bool is_cast;

   Type(const string &_name) : name(_name), ptr(0), is_const(false), is_cast(false) {};
   virtual void print();
   virtual void print(const string &var);

   virtual void rename(const string &oldname, const string &newname);
};

struct Expression : public AstItem {
   virtual ~Expression() {};
   virtual void print();
};

struct NameExpr : public Expression {
   string name;
   bool global;

   NameExpr(const string &var, bool _global = false);

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct FuncNameExpr : public NameExpr {

   FuncNameExpr(const string &var) : NameExpr(var) {};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct BinaryExpr : public Expression {
   const string op;
   Expression *lhs;
   Expression *rhs;

   BinaryExpr(const string &binop, Expression *left, Expression *right) : op(binop), lhs(left), rhs(right) {};
   ~BinaryExpr() {delete lhs; delete rhs;}

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct UnaryExpr : public Expression {
   const string op;
   Expression *expr;

   UnaryExpr(const string &unop, Expression *ex) : op(unop), expr(ex) {};
   ~UnaryExpr() {delete expr;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct ParenExpr : public Expression {
   Expression *inner;

   ParenExpr(Expression *_inner) : inner(_inner) {};
   ~ParenExpr() {delete inner;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct ArrayExpr : public Expression {
   Expression *array;
   Expression *index;

   ArrayExpr(Expression *_array, Expression *_index) : array(_array), index(_index) {};
   ~ArrayExpr() {delete array; delete index;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct BreakStatement : public Statement {
   virtual void print();
};

struct LabelExpr : public Expression {
   string label;

   LabelExpr(const string &_label) : label(_label) {};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct LabelStatement : public Statement {
   string label;

   LabelStatement(const string &_label) : label(_label) {
      no_indent = true;
      no_semi = true;
   };

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct GotoStatement : public Statement {
   Expression *label;

   ~GotoStatement() {delete label;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct Block : public AstItem {
   vector<Statement*> block;

   ~Block();

   void push_back(Statement *s) {block.push_back(s);};
   Statement * &back() {return block.back();};
   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct VarDecl : public Statement {
   Type *type;
   //Expression *var;
   NameExpr *var;
   Expression *init;

   VarDecl() : type(NULL), var(NULL), init(NULL) {};
   ~VarDecl();

   virtual void print();

   const string &getName();

   virtual void rename(const string &oldname, const string &newname);
};

struct Funcproto : public AstItem {
   Type *return_type;
   vector<string> keywords;
   string name;
   vector<VarDecl*> parameters;

   Funcproto() : return_type(NULL) {};
   ~Funcproto();

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct CastExpr : public Expression {
   Type *type;

   CastExpr(const string &typ);
   ~CastExpr();

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct CommaExpr : public Expression {
   Expression *lhs;
   Expression *rhs;

   CommaExpr(Expression *_lhs, Expression *_rhs) : lhs(_lhs), rhs(_rhs) {};
   ~CommaExpr();

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct TypeCast : public Expression {
   Expression *type;
   Expression *expr;

   TypeCast(Expression *_type, Expression *_expr) : type(_type), expr(_expr) {};
   ~TypeCast() {delete type; delete expr;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct CallExpr : public Expression {
   Expression *func;
   Expression *args; //should be a ParenExpr
//   vector<Expression*> args;

   CallExpr(Expression *f, Expression *arglist) : func(f), args(arglist) {};
   ~CallExpr();

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct LiteralExpr : public Expression {
   const string val;
   LiteralExpr(const string &literal) : val(literal) {};

   virtual void print();
};

struct IntegerLiteral : public LiteralExpr {
   IntegerLiteral(const string &num) : LiteralExpr(num) {};

   virtual void print();

   uint64_t get_value();
};

struct StringLiteral : public LiteralExpr {
   StringLiteral(const string &str) : LiteralExpr(str) {};

   virtual void print();
};

struct CharExpr : public LiteralExpr {
   CharExpr(const string &chr) : LiteralExpr(chr) {};

   virtual void print();
};

struct EmptyExpr : public Expression {
   virtual void print() {};
};

struct EmptyStatement : public Statement {
   EmptyStatement() {
      no_semi = true;
      no_indent = true;
   };

   virtual void print() {};
};

struct ConditionalStatement : public Statement {
   Expression *cond;
   Block block;

   ConditionalStatement() : cond(NULL) {};
   ~ConditionalStatement() {delete cond;}

   void push_back(Statement *stmt) {block.push_back(stmt);};
   Statement * &back() {return block.back();};

   virtual void rename(const string &oldname, const string &newname);
};

struct Else : public AstItem {
   Block block;

   Else() {no_semi = true;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct If : public ConditionalStatement {
   Else *_else;

   If() : _else(NULL) {no_semi = true;};
   ~If() {delete _else;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct While : public ConditionalStatement {
   While() {no_semi = true;};

   virtual void print();
};

struct DoWhile : public ConditionalStatement {
   DoWhile() {};

   virtual void print();
};

struct Case : public Block {
   string label;
   bool is_default;

   Case(bool _is_default = false) : is_default(_is_default) {};

   virtual void print();
};

struct Switch : public Statement {
   Expression *cond;
   vector<Case*> cases;

   Switch() : cond(NULL) {no_semi = true;};
   ~Switch() {delete cond;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct Return : public Statement {
   Expression *expr;

   Return() : expr(NULL) {};
   ~Return() {delete expr;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct AssignExpr : public Expression {
   Expression *lval;
   Expression *rval;

   AssignExpr(Expression *lhs, Expression *rhs) : lval(lhs), rval(rhs) {};
   ~AssignExpr();

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct ExprStatement : public Statement {
   Expression *expr;

   ExprStatement(Expression *e) : expr(e) {};
   ~ExprStatement();

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

struct Ternary : public Expression {
   Expression *expr;
   Expression *_true;
   Expression *_false;

   Ternary() : expr(NULL), _true(NULL), _false(NULL) {};
   ~Ternary() {delete expr; delete _true; delete _false;};

   virtual void print();

   virtual void rename(const string &oldname, const string &newname);
};

//we are only interested in function trees
//NOT entire program trees
struct Function : public Statement {
   uint64_t addr;
   Funcproto prototype;
   Block block;

   Function(uint64_t ea) : addr(ea) {};

   virtual void print();
   virtual void print(vector<string> *cfunc);

   virtual void rename(const string &oldname, const string &newname);
};

struct XmlElement;
Function *func_from_tree(XmlElement *root, uint64_t addr);

bool is_reserved(const string &word);

VarDecl *find_decl(Function *ast, const string &sword);
VarDecl *find_decl(Function *ast, int col, int line);

#endif
