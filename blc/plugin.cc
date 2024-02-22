/*
   Source for blc IdaPro plugin
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

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif  // USE_DANGEROUS_FUNCTIONS

#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif

#ifndef NO_OBSOLETE_FUNCS
#define NO_OBSOLETE_FUNCS
#endif

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <range.hpp>
#include <frame.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <search.hpp>
#include <diskio.hpp>
#include <segregs.hpp>
#include <xref.hpp>
#include <help.h>
#include <moves.hpp>
#include <lines.hpp>

#include <stdlib.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <map>
#include <set>

//#define DEBUG 1

#include "plugin.hh"
#include "ast.hh"

#if defined(__NT__)                   // MS Windows
#define DIRSEP "\\"
#else
#define DIRSEP "/"
#endif

using std::iostream;
using std::ifstream;
using std::istreambuf_iterator;
using std::map;
using std::set;

struct blc_plugmod_t : public plugmod_t {

    bool processing_name_change;

    blc_plugmod_t();

    /// Invoke the plugin.
    virtual bool idaapi run(size_t arg);

    /// Virtual destructor.
    virtual ~blc_plugmod_t();
};

blc_plugmod_t *plug;

struct LocalVar {
    string ghidra_name;
    string current_name;  //current display name in disassembly display
    ea_t offset;      //offset into stack frame if stack var (BADADDR otherwise)

    LocalVar(const string &gname, const string &iname, ea_t _offset = BADADDR) :
        ghidra_name(gname), current_name(iname), offset(_offset) {};
};

struct Decompiled {
    Function *ast;
    func_t *ida_func;
    strvec_t *sv;       //text of the decompiled function displayed in a custom_viewer
    map<string, LocalVar*> locals;

    Decompiled(Function *f, func_t *func) : ast(f), ida_func(func), sv(NULL) {};
    ~Decompiled();

    void set_ud(strvec_t *ud);
    strvec_t *get_ud() {return sv;};
};

Decompiled::~Decompiled() {
    delete ast;
    for (map<string, LocalVar*>::iterator i = locals.begin(); i != locals.end(); i++) {
        delete i->second;
    }
    delete sv;
}

void Decompiled::set_ud(strvec_t *ud) {
    delete sv;
    sv = ud;
}

void decompile_at(ea_t ea, TWidget *w = NULL);
int do_ida_rename(qstring &name, ea_t func);

static map<string,uint32_t> type_sizes;
static map<TWidget*,qvector<ea_t> > histories;
static map<TWidget*,string> views;
static map<TWidget*,Decompiled*> function_map;
static set<string> titles;

arch_map_t arch_map;

bool is_current_function(ea_t ea) {
    func_t *f = get_func(ea);
    if (f) {
        for (map<TWidget*,Decompiled*>::iterator i = function_map.begin(); i != function_map.end(); i++) {
            Decompiled *dec = i->second;
            if (dec->ida_func->start_ea == f->start_ea) {
                return true;
            }
        }
    }
    return false;
}

static string get_available_title() {
    string title("A");
    while (titles.find(title) != titles.end()) {
       int i = 0;
       while (true) {
           title[i] += 1;
           if (title[i] > 'Z') {
               title[i] = 'A';
               if (title.length() == i) {
                   title.push_back('A');
                   break;
               }
               else {
                   i++;
               }
           }
           else {
               break;
           }
        }
    }
    return title;
}

//---------------------------------------------------------------------------
// get the word under the (keyboard or mouse) cursor
static bool get_current_word(TWidget *v, bool mouse, qstring &word, qstring *line) {
    // query the cursor position
    int x, y;
    if (get_custom_viewer_place(v, mouse, &x, &y) == NULL) {
        return false;
    }
    // query the line at the cursor
    tag_remove(line, get_custom_viewer_curline(v, mouse));
    if (x >= line->length()) {
        return false;
    }
    char *ptr = line->begin() + x;
    char *end = ptr;
    // find the end of the word
    while ((qisalnum(*end) || *end == '_') && *end != '\0') {
        end++;
    }

    if (end == ptr) {
        return false;
    }

    // find the beginning of the word
    while (ptr > line->begin() && (qisalnum(ptr[-1]) || ptr[-1] == '_')) {
        ptr--;
    }
    if (!qisalpha(*ptr) && *ptr != '_') {
        //starts with a digit
        return false;
    }
    word = qstring(ptr, end - ptr);
    return true;
}

static bool navigate_to_word(TWidget *w, bool cursor) {
    qstring word;
    qstring line;
    if (get_current_word(w, cursor, word, &line)) {
        ea_t ea = get_name_ea(BADADDR, word.c_str());
        if (ea != BADADDR) {
            if (is_function_start(ea) && !is_extern_addr(ea)) {
               map<TWidget*,qvector<ea_t> >::iterator mi = histories.find(w);
               if (mi == histories.end() || mi->second.size() == 0 || mi->second.back() != ea) {
                   histories[w].push_back(ea);
                   decompile_at(ea, w);
               }
            }
            else {
                jumpto(ea);
            }
            return true;
        }
    }
    return false;
}

void split(const char *str, vector<string> &parts, char ch = '\n') {
    const char *ptr;
    size_t begin = 0;
    while (true) {
        ptr = strchr(str, ch);
        if (ptr == NULL) {
            break;
        }
        parts.push_back(string(str, ptr));
        str = ptr + 1;
    }
    if (*str) {
        parts.push_back(str);
    }
}

strvec_t *generate_code(Decompiled *dec) {
    vector<string> code;
    dec->ast->print(&code);
    strvec_t *sv = new strvec_t();
    netnode nn(dec->ida_func->start_ea);  // for access to stored comments
    ea_t lineno = 0;
    for (vector<string>::iterator si = code.begin(); si != code.end(); si++) {
        qstring comment;
        ssize_t sz = nn.supstr(&comment, lineno, '#');
        if (sz > 0) {
            // create new string by appending comment w/ comment color to code string
            qstring line = si->c_str();

            ssize_t len = tag_strlen(line.c_str());
            vector<string> parts;
            split(comment.c_str(), parts);

            line.cat_sprnt("  %c%c// %s%c%c", COLOR_ON, COLOR_CREF, parts[0].c_str(), COLOR_OFF, COLOR_CREF);
            sv->push_back(simpleline_t(line.c_str()));
            for (int i = 1; i < parts.size(); i++) {
                qstring cmt;
                cmt.sprnt("%*s  %c%c// %s%c%c", len, "", COLOR_ON, COLOR_CREF, parts[i].c_str(), COLOR_OFF, COLOR_CREF);
                sv->push_back(simpleline_t(cmt.c_str()));
                lineno++;
            }
        }
        else {
             sv->push_back(simpleline_t(si->c_str()));
        }
        lineno++;
    }
    dec->set_ud(sv);
    return sv;
}

void refresh_view(TWidget *w, Decompiled *dec) {
    strvec_t *sv = generate_code(dec);
    callui(ui_custom_viewer_set_userdata, w, sv);
    refresh_custom_viewer(w);
    repaint_custom_viewer(w);
}

// used to update local variable names in response to name changes in the disassembler
// try to find a match based on frame offsets
void update_local_name(func_t *f, ea_t offset, const char *newname) {
    for (map<TWidget*,Decompiled*>::iterator i = function_map.begin(); i != function_map.end(); i++) {
        Decompiled *dec = i->second;
        if (dec->ida_func->start_ea == f->start_ea) {
            msg("update_local_name, containing function is currently open it widgit\n");
            for (map<string,LocalVar*>::iterator mi = dec->locals.begin(); mi != dec->locals.end(); mi++) {
                LocalVar *lv = mi->second;
                if (lv->offset == offset) { //stack var
                    dec->ast->rename(lv->current_name, newname);
                    dec->locals.erase(lv->current_name);
                    lv->current_name = newname;
                    dec->locals[newname] = lv;
                    refresh_view(i->first, dec);
                }
            }

        }
    }
}

int find_cmt_start(Decompiled *dec, int y) {
    while (y >= 0) {
        qstring clean;
        tag_remove(&clean, (*dec->sv)[y].line);
        const char *ptr = clean.c_str();
        while (*ptr) {
            if (isspace(*ptr)) {
                ptr++;
            }
            else if (strncmp(ptr, "//", 2) == 0) {
                break;
            }
            else {
                return y;
            }
        }
        y--;
    }
    return -1;
}

bool add_new_comment(TWidget *w) {
    //Add eol comment on current line
    int x, y;
    // get_custom_viewer_place returns a position in the visible portion of the listing, NOT an absolute
    // position within the entire body of text that populates the listing
    place_t *pl = get_custom_viewer_place(w, false, &x, &y);
    tcc_place_type_t pt = get_viewer_place_type(w);
    if (pl && pt == TCCPT_SIMPLELINE_PLACE) {
        simpleline_place_t *slp = (simpleline_place_t*)pl;
        y = slp->n;
    }
    else {
        //msg("Couldn't retrieve line number\n");
        return false;
    }
    Decompiled *dec = function_map[w];  //the ast for the function we are editing
    netnode nn(dec->ida_func->start_ea);  // for access to stored comments
    y = find_cmt_start(dec, y);
    if (y < 0) {
        msg("Failed to find comment start line\n");
        return false;
    }
    qstring comment;
    ssize_t sz = nn.supstr(&comment, y, '#');
    vector<string> parts;
    split(comment.c_str(), parts);
    size_t old_parts = parts.size();
    if (old_parts == 0) {
        old_parts = 1;
    }
    parts.clear();
    if (ask_text(&comment, 1024, comment.c_str(), "Please enter comment")) {
        split(comment.c_str(), parts);
        size_t new_parts = parts.size();
        if (new_parts == 0) {
            new_parts = 1;
        }
        if (new_parts != old_parts) {
            //need to adjust the nodeidx of all comments at lines higher than this one
            ssize_t delta = new_parts - old_parts;
            nodeidx_t last = nn.suplast('#');
            if (last != BADNODE && last > (unsigned int)y) {
                nodeidx_t begin = y + old_parts;
                nodeidx_t end = last + 1;
                nodeidx_t range = end - begin;
                nn.supshift(begin, begin + delta, range, '#');
            }
        }
        nn.supset(y, comment.c_str(), 0, '#');
        refresh_view(w, dec);
    }
    return true;
}

//---------------------------------------------------------------------------
// Keyboard callback
static bool idaapi ct_keyboard(TWidget *w, int key, int shift, void *ud) {
    ea_t addr = 0;
    strvec_t *sv = (strvec_t *)ud;
    if (shift == 0) {
//        msg("ct_keyboard handling 0x%x\n", key);
        switch (key) {
            case 'G':
                if (ask_addr(&addr, "Jump address")) {
                    func_t *f = get_func(addr);
                    if (f) {
                        decompile_at(f->start_ea, w);
                    }
                }
                return true;
            case 'N': { //rename the thing under the cursor
                Decompiled *dec = function_map[w];
                qstring word;
                qstring line;
                bool refresh = false;
                if (get_current_word(w, false, word, &line)) {
                    string sword(word.c_str());
 //                   msg("Try to rename: %s\n", word.c_str());
                    if (!is_reserved(sword)) { //can't rename to a reserved word
                        qstring new_name(word);
                        map<string,LocalVar*>::iterator mi = dec->locals.find(sword);
                        if (mi != dec->locals.end()) {
 //                           msg("%s is a local\n", word.c_str());
                            LocalVar *lv = mi->second;
                            if (ask_str(&word, HIST_IDENT, "Please enter item name") && sword != word.c_str()) {
                                string newname(word.c_str());
                                //need to make sure new name will be legal
                                if (is_reserved(newname) || dec->locals.find(newname) != dec->locals.end() ||
                                     get_name_ea(BADADDR, newname.c_str()) != BADADDR) {
 //                                   msg("rename fail 1\n");
                                    return true;
                                }
                                if (lv->offset != BADADDR) { //stack var
 //                                   msg("renaming a stack var %s to %s\n", sword.c_str(), word.c_str());
                                    plug->processing_name_change = true;
                                    if (set_member_name(get_frame(dec->ida_func), lv->offset, word.c_str())) {
                                        lv->current_name = newname;
                                        dec->locals.erase(sword);
                                        dec->locals[newname] = lv;
                                        dec->ast->rename(sword, newname);
                                        refresh = true;
                                    }
                                    else {
 //                                       msg("set_member_name failed\n");
                                    }
                                }
                                else { //not stack var, reg var??
                                    qstring iname;
                                    netnode nn(dec->ida_func->start_ea);
 //                                   msg("renaming a reg var %s to %s\n", sword.c_str(), word.c_str());
                                    lv->current_name = newname;
                                    dec->locals.erase(sword);
                                    dec->locals[word.c_str()] = lv;
                                    dec->ast->rename(sword, word.c_str());
                                    nn.hashset(lv->ghidra_name.c_str(), word.c_str());
                                    refresh = true;
                                }
                            }
                        }
                        else if (do_ida_rename(new_name, dec->ida_func->start_ea) == 2) {
                            //renming a global
                            string snew_name(new_name.c_str());
                            dec->ast->rename(sword, snew_name);
 //                           msg("rename: %s -> %s\n", word.c_str(), new_name.c_str());
                            refresh = true;
                        }
                        else {
                        }
                    }
                }
                if (refresh) {
                    refresh_view(w, dec);
                }
                return true;
            }
            case 'X': { //Show xrefs for the thing under the cursor
                Decompiled *dec = function_map[w];
                qstring word;
                qstring line;
                if (get_current_word(w, false, word, &line)) {
 //                   msg("Current word is %s\n", word.c_str());
                    string sword(word.c_str());
                    if (!is_reserved(sword)) { //no xrefs to a reserved word
                        map<string,LocalVar*>::iterator mi = dec->locals.find(sword);
                        if (mi == dec->locals.end()) { // not a local that we know of
                            // show xrefs to word/sword
                            ea_t to = get_name_ea(BADADDR, word.c_str());
                            if (to != BADADDR) {
                                ea_t from = choose_xref(to);
                                if (from != BADADDR) {
 //                                   msg("User selected xref 0x%lx\n", from);
                                    ea_t fstart = (ea_t)get_func_start(from);
                                    if (fstart != BADADDR) {
                                        decompile_at(fstart, w);
                                    }
                                    else {
                                        //probably global, but not a function, need
                                        //to jump in disassembly window rather than decompile window
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    msg("No word detected\n");
                }
                return true;
            }
            case 'Y': { //Set type for the thing under the cursor
                Decompiled *dec = function_map[w];  //the ast for the function we are editing
                qstring word;
                qstring line;
                if (get_current_word(w, false, word, &line)) {
                    //need to determine the thing being typed along with it's old type
                    //user may have selected the type name at a variable's declaration,
                    //or the user may have selected the variable name at its declaration
                    //or some place it is used, so we need to find the variable's declaration
                    //node in the ast (unless it's a global) so that we can change the Type
                    //node within the declaration node.

                    int x = -1;
                    int y = -1;

                    place_t *pl = get_custom_viewer_place(w, false, &x, &y);
                    tcc_place_type_t pt = get_viewer_place_type(w);
                    if (pl && pt == TCCPT_SIMPLELINE_PLACE) {
                        simpleline_place_t *slp = (simpleline_place_t*)pl;
                        y = slp->n;
                    }
                    else {
                        msg("Couldn't retrieve line number\n");
                        return false;
                    }

                    //indent doesn't get factored into ast x/y data
                    for (const char *cptr = line.c_str(); *cptr == ' '; cptr++) {
                        x--;
                    }

                    string sword(word.c_str());
                    map<string,LocalVar*>::iterator mi = dec->locals.find(sword);
                    VarDecl *decl = NULL;
                    if (mi != dec->locals.end()) {
 //                       msg("Find decl by name (%s)\n", sword.c_str());
                        decl = find_decl(dec->ast, sword);
                    }
                    else {
 //                       msg("Find decl by x,y (%d,%d)\n", x, y);
                        decl = find_decl(dec->ast, x, y);
                    }
                    if (decl == NULL) {
                        //last chance - see if word refers to a global, then ask IDA its type
                    }
                    else {
 //                      msg("You seem to be referring to this decl: %s on line %d col %d\n", decl->var->name.c_str(), decl->line_begin, decl->col_start);
                    }
#if 0
//not  ready yet
                    //need to get string representation of the decl (if type is known) to display to user
                    if (ask_str(&word, HIST_IDENT, "Please enter the type declaration")) {
                        //now we need to parse what the user entered to extract only type related info
                        //then determine whether the user entered a type known to ida, and if so
                        //update the ast to change the variable's type. If the variable is a stack variable,
                        //global variable, or function parameter, also change the type in IDA.
                        //If the type is for a register variable, then update the variable's type in a
                        //netnode (like the variable name map)

                        //use parse_decl to parse user text into a type
                        //then will need to extract IDA's tinfo_t information back to an updated ast Type node
                    }
#endif
                }
               return true;
            }
            case ';':
            case IK_DIVIDE: {
                //Add eol comment on current line
                add_new_comment(w);
                return true;
            }
            case IK_ESCAPE: {
                map<TWidget*,qvector<ea_t> >::iterator mi = histories.find(w);
                if (mi != histories.end()) {
                    qvector<ea_t> &v = mi->second;
                    if (v.size() == 1) {
                        close_widget(w, WCLS_DONT_SAVE_SIZE | WCLS_CLOSE_LATER);
                        string t = views[w];
                        views.erase(w);
                        delete function_map[w];
                        function_map.erase(w);
                        titles.erase(t);
                    }
                    else {
                        v.pop_back();
                        decompile_at(v.back(), w);
                    }
                    return true;
                }
                break;
            }
            case IK_RETURN: {  //jump to symbol under cursor
                return navigate_to_word(w, false);
            }
            default:
//               msg("Detected key press: 0x%x\n", key);
               break;
        }
    }
    else {
//        msg("ct_keyboard handling shift 0x%x\n", key);
        switch (key) {
            case '3':  { // shift-3 == '#'
                add_new_comment(w);
                return true;
            }
        }
    }
    return false;
}

static bool idaapi ct_dblclick(TWidget *cv, int shift, void *ud) {
//   msg("Double clicked on: %s\n", word.c_str());
   return navigate_to_word(cv, true);
}

static const custom_viewer_handlers_t handlers(
        ct_keyboard,
        NULL, // popup
        NULL, // mouse_moved
        NULL, // click
        ct_dblclick, // dblclick
        NULL, //ct_curpos,
        NULL, // close
        NULL, // help
        NULL);// adjust_place

string ghidra_dir;

// maps ida processor id to Ghidra processor name (see Ghidra ldefs files)
map<int,string> proc_map;

map<int,string> return_reg_map;

static const char *name_dialog;

//get the format string for IDA's standard rename dialog
void find_ida_name_dialog() {
    help_t i;
    for (i = 0; ; i++) {
        const char *hlp = itext(i);
        const char *lf = strchr(hlp, '\n');
        if (lf != NULL) {
            lf++;
            if (strncmp("Rename address\n", lf, 15) == 0) {
               name_dialog = hlp;
 //               msg("Found:\n%s\n", hlp);
                break;
            }
        }
    }
}

// return -1 - name is not associated with a symbol
// return 0  - duplicate name
// return 1  - no change
// return 2  - name changed
// return 3  - new name, but couldn't change it
int do_ida_rename(qstring &name, ea_t func) {
    ea_t name_ea = get_name_ea(func, name.c_str());
    if (name_ea == BADADDR) {
        //somehow the original name is invalid
//        msg("rename: %s has no addr\n", name.c_str());
        return -1;
    }
    qstring orig = name;
    bool res = ask_str(&name, HIST_IDENT, "Please enter item name");
    if (res && name != orig) {
        ea_t new_name_ea = get_name_ea(func, name.c_str());
        if (new_name_ea != BADADDR) {
            //new name is same as existing name
//            msg("rename: new name already in use\n", name.c_str());
            return 0;
        }
//        msg("Custom rename: %s at adddress 0x%zx\n", name.c_str(), name_ea);
        plug->processing_name_change = true;
        res = set_name(name_ea, name.c_str());
        return res ? 2 : 3;
    }
//    msg("rename: no change\n");
    return 1;
}

func_t *func_from_frame(struc_t *frame) {
    if (frame->props & SF_FRAME) {
        size_t qty = get_func_qty();
        for (size_t i = 0; i < qty; i++) {
           func_t *f = getn_func(i);
           if (f->frame == frame->id) return f;
        }
    }
    return NULL;
}

ssize_t idaapi blc_hook(void *user_data, int notification_code, va_list va) {
    blc_plugmod_t *blc = (blc_plugmod_t*)user_data;
    switch (notification_code) {
        case idb_event::renamed: {
            //global names, local names, and struct member renames all land here
            if (blc->processing_name_change) {
                blc->processing_name_change = false;
                break;
            }
            string nm;
            ea_t ea = va_arg(va, ea_t);
            const char *name = va_arg(va, const char *);
            bool local = va_arg(va, int) != 0;
            const char *oldname = va_arg(va, const char *);

            if (local) {
                break;
            }
            if (is_named_addr(ea, nm)) {
                // probably a global rather than a struct member
                //msg("rename: 0x%lx: %s ->  %s\n", ea, name, oldname);
            }
            else {
                //msg("rename: 0x%lx: %s ->  %s\n", ea, name, oldname);
            }
            break;
        }
        case idb_event::struc_member_renamed: {
            if (blc->processing_name_change) {
                break;
            }
            struc_t *sptr =  va_arg(va, struc_t *);
            member_t *mptr =  va_arg(va, member_t *);
//            const char *newname = va_arg(va, const char*);
            func_t *pfn = func_from_frame(sptr);
            if (pfn) {
                //renamed a function local
                qstring name;
                get_member_name(&name, mptr->id);
                //msg("stack var rename in 0x%x becomes %s (0x%x, 0x%x)\n", pfn->start_ea, name.c_str(), sptr->id, mptr->id);
                //update_local_name(pfn, mptr->soff, name.c_str());
            }
            break;
        }
    }
    return 0;
}


void init_ida_ghidra() {
    const char *ghidra = getenv("GHIDRA_DIR");
    if (ghidra) {
        ghidra_dir = ghidra;
    }
    else {
        ghidra_dir = idadir("plugins");
    }
 //   find_ida_name_dialog();

    arch_map[PLFM_MIPS] = mips_setup;

    proc_map[PLFM_6502] = "6502";
    proc_map[PLFM_68K] = "68000";
    proc_map[PLFM_6800] = "6805";
    //proc_map[PLFM_xxx] = "8048";
    proc_map[PLFM_8051] = "8051";
    //proc_map[PLFM_Z80] = "8085";
    proc_map[PLFM_ARM] = "ARM";
    //proc_map[PLFM_ARM] = "AARCH64";
    proc_map[PLFM_AVR] = "avr8";
    proc_map[PLFM_CR16] = "CR16";
    proc_map[PLFM_DALVIK] = "Dalvik";
    proc_map[PLFM_JAVA] = "JVM";
    proc_map[PLFM_MIPS] = "MIPS";
    proc_map[PLFM_HPPA] = "pa-risc";
    proc_map[PLFM_PIC] = "PIC";
    proc_map[PLFM_PPC] = "PowerPC";
    proc_map[PLFM_SPARC] = "sparc";
    proc_map[PLFM_MSP430] = "TI_MSP430";
    proc_map[PLFM_TRICORE] = "tricore";
    proc_map[PLFM_386] = "x86";
    proc_map[PLFM_Z80] = "Z80";

    return_reg_map[PLFM_6502] = "6502";
    return_reg_map[PLFM_68K] = "68000";
    return_reg_map[PLFM_6800] = "6805";
    //return_reg_map[PLFM_xxx] = "8048";
    return_reg_map[PLFM_8051] = "8051";
    //return_reg_map[PLFM_Z80] = "8085";
    return_reg_map[PLFM_ARM] = "r0:r0:r0:r0";
    //return_reg_map[PLFM_ARM] = "r0:r0:r0:r0";
    return_reg_map[PLFM_AVR] = "avr8";
    return_reg_map[PLFM_CR16] = "CR16";
    return_reg_map[PLFM_DALVIK] = "Dalvik";
    return_reg_map[PLFM_JAVA] = "JVM";
    return_reg_map[PLFM_MIPS] = "v0:v0:v0:v0";
    return_reg_map[PLFM_HPPA] = "PA-RISC";
    return_reg_map[PLFM_PIC] = "PIC";
    return_reg_map[PLFM_PPC] = "PowerPC";
    return_reg_map[PLFM_SPARC] = "Sparc";
    return_reg_map[PLFM_MSP430] = "TI_MSP430";
    return_reg_map[PLFM_TRICORE] = "tricore";
    return_reg_map[PLFM_386] = "al:ax:eax:rax";
    return_reg_map[PLFM_Z80] = "Z80";

    type_sizes["void"] = 1;
    type_sizes["bool"] = 1;
    type_sizes["uint1"] = 1;
    type_sizes["uint2"] = 2;
    type_sizes["uint4"] = 4;
    type_sizes["uint8"] = 8;
    type_sizes["int1"] = 1;
    type_sizes["int2"] = 2;
    type_sizes["int4"] = 4;
    type_sizes["int8"] = 8;
    type_sizes["float4"] = 4;
    type_sizes["float8"] = 8;
    type_sizes["float10"] = 10;
    type_sizes["float16"] = 16;
    type_sizes["xunknown1"] = 1;
    type_sizes["xunknown2"] = 2;
    type_sizes["xunknown4"] = 4;
    type_sizes["xunknown8"] = 8;
    type_sizes["code"] = 1;
    type_sizes["char"] = 1;
    type_sizes["wchar2"] = 2;
    type_sizes["wchar4"] = 4;
}

int get_proc_id() {
    return PH.id;
}

#if IDA_SDK_VERSION < 760
inline uint inf_get_app_bitness(void) // return 16, 32, or 64
{
#ifdef __EA64__
    uint32 f = getinf(INF_LFLAGS) & (LFLG_PC_FLAT | LFLG_64BIT);
    return f == 0 ? 16 : f == LFLG_PC_FLAT ? 32 : 64;
#else
    return getinf_flag(INF_LFLAGS, LFLG_PC_FLAT) ? 32 : 16;
#endif
}
#endif

bool get_saved_sleigh_id(string &sleigh) {
    qstring sleigh_id;
    netnode nn(" $ sleigh_id", 0, true);
    ssize_t sz = nn.supstr(&sleigh_id, 0x54321, 'G');
    sleigh = sleigh_id.c_str();
    return sleigh.size() > 1;
}

bool set_saved_sleigh_id(string &sleigh) {
    qstring qsleigh_id;
    netnode nn(" $ sleigh_id", 0, true);
    nn.supset(0x54321, sleigh.c_str(), 0, 'G');
    return true;
}

bool get_sleigh_id(string &sleigh) {
    sleigh.clear();
    int proc_id = get_proc_id();
    msg("Searching for proc id: 0x%x\n", proc_id);
    map<int,string>::iterator proc = proc_map.find(proc_id);
    if (proc == proc_map.end()) {
        return false;
    }
    compiler_info_t cc;
    inf_get_cc(&cc);
    int app_bitness = inf_get_app_bitness();
    bool is_64 = app_bitness == 64;
    bool is_be = inf_is_be();
    filetype_t ftype = inf_get_filetype();

    sleigh = proc->second + (is_be ? ":BE" : ":LE");

    switch (proc_id) {
        case PLFM_6502:
            sleigh += ":16:default";
            break;
        case PLFM_68K:
            //options include "default" "MC68030" "MC68020" "Coldfire"
            sleigh += ":32:default";
            break;
        case PLFM_6800:
            sleigh += ":8:default";
            break;
        case PLFM_8051:
            sleigh += ":16:default";
            break;
        case PLFM_ARM:
            //options include "v8" "v8T" "v8LEInstruction" "v7" "v7LEInstruction" "Cortex"
            //                "v6" "v5t" "v5" "v4t" "v4" "default"
            if (is_64) {  //AARCH64
                sleigh = "AARCH64";
                sleigh += (is_be ? ":BE:64:v8A" : ":LE:64:v8A");
            }
            else {
                sleigh += ":32:v7";
            }
            break;
        case PLFM_AVR:
            /*
            id="avr32:BE:32:default"
            id="avr8:LE:16:default"
            id="avr8:LE:16:extended"
            id="avr8:LE:16:atmega256"
            id="avr8:LE:24:xmega"
            */
            if (app_bitness == 32) {
                sleigh = "avr32";
                sleigh += (is_be ? ":BE:32:default" : ":LE:32:default");
            }
            else if (app_bitness == 24) { //is this even possible in IDA?
                sleigh += ":24:xmega";
            }
            else {
                // can we distinguish between extended and atmega256 in ida?
                sleigh += ":16:default";
            }
            break;
        case PLFM_CR16:
            sleigh += ":16:default";
            break;
        case PLFM_DALVIK:
            sleigh += ":32:default";
            break;
        case PLFM_JAVA:
            sleigh += ":32:default";
            break;
        case PLFM_MIPS: {
            //options include "R6" "micro" "64-32addr" "micro64-32addr" "64-32R6addr" "default"
            qstring abi;
            if (get_abi_name(&abi) > 0 && abi.find("n32") == 0) {
                sleigh += ":64:64-32addr";
            }
            else {
                sleigh += is_64 ? ":64:default" : ":32:default";
            }
            break;
        }
        case PLFM_HPPA:
            sleigh += ":32:default";
            break;
        case PLFM_PIC:
            break;
        case PLFM_PPC: {
            //options include "default" "64-32addr" "4xx" "MPC8270" "QUICC" "A2-32addr"
            //                "A2ALT-32addr" "A2ALT" "VLE-32addr" "VLEALT-32addr"
            qstring abi;
            if (get_abi_name(&abi) > 0 && abi.find("xbox") == 0) {
                // ABI name is set to "xbox" for X360 PPC executables
                sleigh += ":64:A2ALT-32addr";
            }
            else {
                sleigh += is_64 ? ":64:default" : ":32:default";
            }
            break;
        }
        case PLFM_SPARC:
            sleigh += is_64 ? ":64" : ":32";
            sleigh += ":default";
            break;
        case PLFM_MSP430:
            sleigh += ":16:default";
            break;
        case PLFM_TRICORE:
            sleigh += ":32:default";
            break;
        case PLFM_386:
            //options include "System Management Mode" "Real Mode" "Protected Mode" "default"
            sleigh += is_64 ? ":64" : (app_bitness == 32 ? ":32" : ":16");
            if (sleigh.find(":16") != string::npos) {
                sleigh += ":Real Mode";
            }
            else {
                sleigh += ":default";
            }

            if (cc.id == COMP_BC) {
                sleigh += ":borlandcpp";
            }
            else if (cc.id == COMP_MS) {
                sleigh += ":windows";
            }
            else if (cc.id == COMP_GNU) {
                sleigh += ":gcc";
            }
            break;
        case PLFM_Z80:
            break;
        default:
            return false;
    }
    msg("Using sleigh id: %s\n", sleigh.c_str());
    return true;
}

void get_ida_bytes(uint8_t *buf, uint64_t size, uint64_t ea) {
    get_bytes(buf, size, (ea_t)ea);
}

bool does_func_return(void *func) {
    func_t *f = (func_t*)func;
    return func_does_return(f->start_ea);
}

uint64_t get_func_start(void *func) {
    func_t *f = (func_t*)func;
    return f->start_ea;
}

uint64_t get_func_start(uint64_t ea) {
    func_t *f = get_func((ea_t)ea);
    return f ? f->start_ea : BADADDR;
}

uint64_t get_func_end(uint64_t ea) {
    func_t *f = get_func((ea_t)ea);
    return f ? f->end_ea : BADADDR;
}

//Create a Ghidra to Ida name mapping for a single local variable (including formal parameters)
void map_var_from_decl(Decompiled *dec, VarDecl *decl) {
    Function *ast = dec->ast;
    func_t *func = dec->ida_func;
    struc_t *frame = get_frame(func);
    ea_t ra = frame_off_retaddr(func);
    const string gname = decl->getName();
//    msg("Ghidra name is: %s\n", gname.c_str());
    size_t stack = gname.find("Stack");
    LocalVar *lv = new LocalVar(gname, gname);  //default current name will be ghidra name
    if (stack != string::npos) {         //if it's a stack var, change current to ida name
        stack += 5;
        if (gname[stack] == '_') {
            stack++;                // should probably bump this until we find a hex digit
        }
        uint32_t stackoff = strtoul(&gname[stack], NULL, 16);   //always translate as hex, names do not contain 0x
//        msg("Stack offset computed to be: 0x%x\n", stackoff);
        member_t *var = get_member(frame, ra - stackoff);
        lv->offset = ra - stackoff;
        if (var) {                        //now we know there's an ida name assigned
            qstring iname;
            get_member_name(&iname, var->id);
//            msg("member was found named: %s\n", iname.c_str());
            ast->rename(gname, iname.c_str());
            dec->locals[iname.c_str()] = lv;
            lv->current_name = iname.c_str();
        }
        else {  //ghidra says there's a variable here, let's name it in ida
            //TODO - need to compute sizeof(decl) to properly create
            //       the new data member
            qstring iname;
            iname.sprnt("var_%X", stackoff - func->frregs);
//            msg("member was not found renaming to: %s\n", iname.c_str());
            if (add_struc_member(frame, iname.c_str(), ra - stackoff, byte_flag(), NULL, 1) == 0) {
                ast->rename(gname, iname.c_str());
                dec->locals[iname.c_str()] = lv;
                lv->current_name = iname.c_str();
            }
            else {
                dec->locals[gname] = lv;
            }
        }
    }
    else {  //handle non-stack (register) local variables
        netnode nn(dec->ida_func->start_ea);
        qstring iname;
        if (nn.hashstr(&iname, gname.c_str()) <= 0) {
            //no existing mapping
            dec->locals[gname] = lv;
        }
        else {
            //we already have a mapping for this ghidra variable
            ast->rename(gname, iname.c_str());
            dec->locals[iname.c_str()] = lv;
            lv->current_name = iname.c_str();
        }
    }
}

void map_ghidra_to_ida(Decompiled *dec) {
    Function *ast = dec->ast;
    vector<Statement*> &bk = ast->block.block;
    vector<VarDecl*> &parms = ast->prototype.parameters;

    //add mappings for formal parameter names
    for (vector<VarDecl*>::iterator i = parms.begin(); i != parms.end(); i++) {
        VarDecl *decl = *i;
        map_var_from_decl(dec, decl);
    }

    //add mappings for variable names
    for (vector<Statement*>::iterator i = bk.begin(); i != bk.end(); i++) {
        VarDecl *decl = dynamic_cast<VarDecl*>(*i);
        if (decl) {
            map_var_from_decl(dec, decl);
        }
        else {
            break;
        }
    }
}

void decompile_at(ea_t addr, TWidget *w) {
    func_t *func = get_func(addr);
    Function *ast = NULL;
    if (func) {
        int res = do_decompile(func->start_ea, func->end_ea, &ast);
        if (ast) {
#ifdef DEBUG
            msg("got a Functon tree!\n");
#endif
            Decompiled *dec = new Decompiled(ast, func);

            //now try to map ghidra stack variable names to ida stack variable names
            //msg("mapping ida names to ghidra names\n");
            map_ghidra_to_ida(dec);

            strvec_t *sv = generate_code(dec);

            qstring func_name;
            qstring fmt;
            get_func_name(&func_name, func->start_ea);
            string title = get_available_title();
            fmt.sprnt("Ghidra code  - %s", title.c_str());   // make the suffix change with more windows

            simpleline_place_t s1;
            simpleline_place_t s2((int)(sv->size() - 1));

            if (w == NULL) {
                 w = create_custom_viewer(fmt.c_str(), &s1, &s2,
                                          &s1, NULL, sv, &handlers, sv);
                 TWidget *code_view = create_code_viewer(w);
                 set_code_viewer_is_source(code_view);
                 display_widget(code_view, WOPN_DP_TAB);
                 histories[w].push_back(addr);
                 views[w] = title;
                 titles.insert(title);
            }
            else {
                 callui(ui_custom_viewer_set_userdata, w, sv);
                 refresh_custom_viewer(w);
                 repaint_custom_viewer(w);
                 delete function_map[w];
            }
            function_map[w] = dec;
        }
#ifdef DEBUG
        msg("do_decompile returned: %d\n", res);
#endif
    }
    else {
#ifdef DEBUG
        msg("do_decompile failed to return a function\n");
#endif
    }
}

const char *tag_remove(const char *tagged) {
    static qstring ll;
    tag_remove(&ll, tagged);
    return ll.c_str();
}

blc_plugmod_t::blc_plugmod_t() {
    processing_name_change = false;
    hook_to_notification_point(HT_IDB, blc_hook, this);
}

plugmod_t *idaapi blc_init(void) {
    //do ida related init
    init_ida_ghidra();

    if (ghidra_init()) {
        plug = new blc_plugmod_t();
        return plug;
    }
    else {
        return NULL;
    }
}

blc_plugmod_t::~blc_plugmod_t(void) {
    unhook_from_notification_point(HT_IDB, blc_hook, this);
    ghidra_term();
}

bool idaapi blc_plugmod_t::run(size_t /*arg*/) {
    ea_t addr = get_screen_ea();
#ifdef DEBUG
    msg("decompile_at 0x%llx\n", (uint64_t)addr);
#endif
    try {
         decompile_at(addr);
    } catch (...) {
        msg("An exception occured while using the Ghidra decompiler. You may want to save your work and restart IDA.\n");
    }
   return true;
}

int64_t get_name(string &name, uint64_t ea, int flags) {
    qstring ida_name;
    int64_t res = get_name(&ida_name, (ea_t)ea, flags);
    if (res > 0) {
       name = ida_name.c_str();
    }
    return res;
}

int64_t get_func_name(string &name, uint64_t ea) {
    qstring ida_name;
    int64_t res = get_func_name(&ida_name, (ea_t)ea);
    if (res > 0) {
        name = ida_name.c_str();
    }
    return res;
}

bool is_function_start(uint64_t ea) {
    func_t *f = get_func((ea_t)ea);
    return f != NULL && f->start_ea == (ea_t)ea;
}

void get_input_file_path(string &path) {
    char buf[512];
    get_input_file_path(buf, sizeof(buf));
    path = buf;
}

bool is_thumb_mode(uint64_t ea) {
   return get_sreg((ea_t)ea, 20) == 1;
}

//is ea a function internal jump target, if so
//return true and place its name in name
//else return false
bool is_code_label(uint64_t ea, string &name) {
    xrefblk_t xr;
    for (bool success = xr.first_to((ea_t)ea, XREF_ALL); success; success = xr.next_to()) {
        if (xr.iscode == 0) {
            break;
        }
        if (xr.type != fl_JN) {
            continue;
        }
        qstring ida_name;
        int64_t res = get_name(&ida_name, (ea_t)ea, GN_LOCAL);
        if (res > 0) {
            name = ida_name.c_str();
            return true;
        }
    }
    return false;
}

bool is_extern_addr(uint64_t ea) {
    qstring sname;
    segment_t *s = getseg(ea);
    if (s) {
        get_segm_name(&sname, s);
        if (sname == "extern") {
            return true;
        }
    }
    return false;
}

bool is_external_ref(uint64_t ea, uint64_t *fptr) {
    ea_t got;
    func_t *pfn = get_func((ea_t)ea);
    if (pfn == NULL) {
        return false;
    }
    if (is_extern_addr(pfn->start_ea)) {
        if (fptr) {
            *fptr = pfn->start_ea;
        }
        return true;
    }
    ea_t _export = calc_thunk_func_target(pfn, &got);
    bool res = _export != BADADDR;
    if (res) {
        if (fptr) {
            *fptr = got;
        }
        msg("0x%zx is external, with got entry at 0x%zx\n", ea, (size_t)got);
    }
    return res;
}

bool is_extern(const string &name) {
    bool res = false;
    ea_t ea = get_name_ea(BADADDR, name.c_str());
    if (ea == BADADDR) {
        return false;
    }
    if (is_function_start(ea)) {
        res = is_external_ref(ea, NULL);
    }
    else {
        res = is_extern_addr(ea);
    }
 //   msg("is_extern called for %s (%d)\n", name.c_str(), res);
    return res;
}

bool address_of(const string &name, uint64_t *addr) {
    bool res = false;
    ea_t ea = get_name_ea(BADADDR, name.c_str());
    if (ea == BADADDR) {
        return false;
    }
    *addr = ea;
    return true;
}

bool is_library_func(const string &name) {
    bool res = false;
    ea_t ea = get_name_ea(BADADDR, name.c_str());
    if (is_function_start(ea)) {
        func_t *f = get_func(ea);
        res = f ? (f->flags & FUNC_LIB) != 0 : false;
    }
    return res;
}

bool is_named_addr(uint64_t ea, string &name) {
    qstring res;
    //a sanity check on ea
    segment_t *s = getseg(0);
    if (s != NULL && ea < s->end_ea) {
        //ea falls in first segment of zero based binary
        //this are generally headers and ea is probably
        //not a pointer but instead just a small number
        return false;
    }
    if (get_name(&res, (ea_t)ea) > 0) {
        name = res.c_str();
        return true;
    }
    return false;
}

bool is_pointer_var(uint64_t ea, uint32_t size, uint64_t *tgt) {
    xrefblk_t xb;
    if (xb.first_from(ea, XREF_DATA) && xb.type == dr_O) {
        // xb.to - contains the referenced address
        *tgt = xb.to;
        return true;
    }
    return false;
}

bool is_read_only(uint64_t ea) {
    qstring sname;
    segment_t *s = getseg(ea);
    if (s) {
        if ((s->perm & SEGPERM_WRITE) == 0) {
            return true;
        }
        //not explicitly read only, so let's make some guesses
        //based on the segment name
        get_segm_name(&sname, s);
        if (sname.find("got") <= 1) {
            return true;
        }
        if (sname.find("rodata") <= 1) {
            return true;
        }
        if (sname.find("rdata") <= 1) {
            return true;
        }
        if (sname.find("idata") <= 1) {
            return true;
        }
        if (sname.find("rel.ro") != qstring::npos) {
            return true;
        }
    }
    return false;
}

bool simplify_deref(const string &name, string &new_name) {
    uint64_t tgt;
    ea_t addr = get_name_ea(BADADDR, name.c_str());
    uint32_t max_ptr_size = (uint32_t)PH.max_ptr_size();
    if (addr != BADADDR && is_read_only(addr) && is_pointer_var(addr, max_ptr_size, &tgt)) {
       if (get_name(new_name, tgt, 0)) {
  //         msg("could simplify *%s to %s\n", name.c_str(), new_name.c_str());
           return true;
       }
    }
    return false;
}

void adjust_thunk_name(string &name) {
    ea_t ea = get_name_ea(BADADDR, name.c_str());
    if (is_function_start(ea)) {
        func_t *f = get_func(ea);
        ea_t fun = calc_thunk_func_target(f, &ea);
        if (fun != BADADDR) {
            qstring tname;
            if (get_name(&tname, fun)) {
                name = tname.c_str();
            }
        }
    }
}

//TODO think about sign extension for values smaller than 8 bytes
bool get_value(uint64_t addr, uint64_t *val) {
    flags_t f = get_full_flags(addr);
    if (is_qword(f)) {
        *val = get_qword(addr);
    }
    else if (is_dword(f)) {
        *val = get_dword(addr);
    }
    else if (is_byte(f)) {
        *val = get_byte(addr);
    }
    else if (is_word(f)) {
        *val = get_word(addr);
    }
    else {
        return false;
    }
    return true;
}

bool get_string(uint64_t addr, string &str) {
    qstring res;
    flags_t f = get_full_flags(addr);
    if (is_strlit(f)) {
        get_strlit_contents(&res, addr, -1, STRTYPE_C);
        str = res.c_str();
        return true;
    }
    else if (!is_data(f)) {
        size_t maxlen = get_max_strlit_length(addr, STRTYPE_C);
        if (maxlen > 4) {
            create_strlit(addr, 0, STRTYPE_C);
            get_strlit_contents(&res, addr, -1, STRTYPE_C);
            str = res.c_str();
            return true;
        }
    }
    return false;
}

bool get_string(string name, string &str) {
    ea_t addr = get_name_ea(BADADDR, name.c_str());
    if (addr != BADADDR) {
        return get_string(addr, str);
    }
    return false;
}

//--------------------------------------------------------------------------
char comment[] = "Ghidra decompiler integration.";

char help[] = "I have nothing to offer.\n";

char wanted_name[] = "Ghidra Decompiler";

char wanted_hotkey[] = "Alt-F3";

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,      // plugin flags
    blc_init,          // initialize
    NULL,              // terminate. this pointer may be NULL.
    NULL,              // invoke plugin
    comment,              // long comment about the plugin
                          // it could appear in the status line
                          // or as a hint
    help,                 // multiline help about the plugin
    wanted_name,          // the preferred short name of the plugin
    wanted_hotkey         // the preferred hotkey to run the plugin
};
