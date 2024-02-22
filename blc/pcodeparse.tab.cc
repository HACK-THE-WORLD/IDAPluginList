/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Substitute the type names.  */
#define YYSTYPE         PCODESTYPE
/* Substitute the variable and function names.  */
#define yyparse         pcodeparse
#define yylex           pcodelex
#define yyerror         pcodeerror
#define yydebug         pcodedebug
#define yynerrs         pcodenerrs
#define yylval          pcodelval
#define yychar          pcodechar

/* First part of user prologue.  */
#line 17 "pcodeparse.y"

#include "pcodeparse.hh"

//#define YYERROR_VERBOSE
namespace ghidra {

extern int pcodelex(void);
static PcodeSnippet *pcode;
extern int pcodeerror(const char *str );

#line 90 "pcodeparse.tab.cc"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif


/* Debug traces.  */
#ifndef PCODEDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define PCODEDEBUG 1
#  else
#   define PCODEDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define PCODEDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined PCODEDEBUG */
#if PCODEDEBUG
extern int pcodedebug;
#endif

/* Token kinds.  */
#ifndef PCODETOKENTYPE
# define PCODETOKENTYPE
  enum pcodetokentype
  {
    PCODEEMPTY = -2,
    PCODEEOF = 0,                  /* "end of file"  */
    PCODEerror = 256,              /* error  */
    PCODEUNDEF = 257,              /* "invalid token"  */
    OP_BOOL_OR = 258,              /* OP_BOOL_OR  */
    OP_BOOL_AND = 259,             /* OP_BOOL_AND  */
    OP_BOOL_XOR = 260,             /* OP_BOOL_XOR  */
    OP_EQUAL = 261,                /* OP_EQUAL  */
    OP_NOTEQUAL = 262,             /* OP_NOTEQUAL  */
    OP_FEQUAL = 263,               /* OP_FEQUAL  */
    OP_FNOTEQUAL = 264,            /* OP_FNOTEQUAL  */
    OP_GREATEQUAL = 265,           /* OP_GREATEQUAL  */
    OP_LESSEQUAL = 266,            /* OP_LESSEQUAL  */
    OP_SLESS = 267,                /* OP_SLESS  */
    OP_SGREATEQUAL = 268,          /* OP_SGREATEQUAL  */
    OP_SLESSEQUAL = 269,           /* OP_SLESSEQUAL  */
    OP_SGREAT = 270,               /* OP_SGREAT  */
    OP_FLESS = 271,                /* OP_FLESS  */
    OP_FGREAT = 272,               /* OP_FGREAT  */
    OP_FLESSEQUAL = 273,           /* OP_FLESSEQUAL  */
    OP_FGREATEQUAL = 274,          /* OP_FGREATEQUAL  */
    OP_LEFT = 275,                 /* OP_LEFT  */
    OP_RIGHT = 276,                /* OP_RIGHT  */
    OP_SRIGHT = 277,               /* OP_SRIGHT  */
    OP_FADD = 278,                 /* OP_FADD  */
    OP_FSUB = 279,                 /* OP_FSUB  */
    OP_SDIV = 280,                 /* OP_SDIV  */
    OP_SREM = 281,                 /* OP_SREM  */
    OP_FMULT = 282,                /* OP_FMULT  */
    OP_FDIV = 283,                 /* OP_FDIV  */
    OP_ZEXT = 284,                 /* OP_ZEXT  */
    OP_CARRY = 285,                /* OP_CARRY  */
    OP_BORROW = 286,               /* OP_BORROW  */
    OP_SEXT = 287,                 /* OP_SEXT  */
    OP_SCARRY = 288,               /* OP_SCARRY  */
    OP_SBORROW = 289,              /* OP_SBORROW  */
    OP_NAN = 290,                  /* OP_NAN  */
    OP_ABS = 291,                  /* OP_ABS  */
    OP_SQRT = 292,                 /* OP_SQRT  */
    OP_CEIL = 293,                 /* OP_CEIL  */
    OP_FLOOR = 294,                /* OP_FLOOR  */
    OP_ROUND = 295,                /* OP_ROUND  */
    OP_INT2FLOAT = 296,            /* OP_INT2FLOAT  */
    OP_FLOAT2FLOAT = 297,          /* OP_FLOAT2FLOAT  */
    OP_TRUNC = 298,                /* OP_TRUNC  */
    OP_NEW = 299,                  /* OP_NEW  */
    BADINTEGER = 300,              /* BADINTEGER  */
    GOTO_KEY = 301,                /* GOTO_KEY  */
    CALL_KEY = 302,                /* CALL_KEY  */
    RETURN_KEY = 303,              /* RETURN_KEY  */
    IF_KEY = 304,                  /* IF_KEY  */
    ENDOFSTREAM = 305,             /* ENDOFSTREAM  */
    LOCAL_KEY = 306,               /* LOCAL_KEY  */
    INTEGER = 307,                 /* INTEGER  */
    STRING = 308,                  /* STRING  */
    SPACESYM = 309,                /* SPACESYM  */
    USEROPSYM = 310,               /* USEROPSYM  */
    VARSYM = 311,                  /* VARSYM  */
    OPERANDSYM = 312,              /* OPERANDSYM  */
    STARTSYM = 313,                /* STARTSYM  */
    ENDSYM = 314,                  /* ENDSYM  */
    NEXT2SYM = 315,                /* NEXT2SYM  */
    LABELSYM = 316                 /* LABELSYM  */
  };
  typedef enum pcodetokentype pcodetoken_kind_t;
#endif

/* Value type.  */
#if ! defined PCODESTYPE && ! defined PCODESTYPE_IS_DECLARED
union PCODESTYPE
{
#line 28 "pcodeparse.y"

  uintb *i;
  string *str;
  vector<ExprTree *> *param;
  StarQuality *starqual;
  VarnodeTpl *varnode;
  ExprTree *tree;
  vector<OpTpl *> *stmt;
  ConstructTpl *sem;

  SpaceSymbol *spacesym;
  UserOpSymbol *useropsym;
  LabelSymbol *labelsym;
  StartSymbol *startsym;
  EndSymbol *endsym;
  Next2Symbol *next2sym;
  OperandSymbol *operandsym;
  VarnodeSymbol *varsym;
  SpecificSymbol *specsym;

#line 227 "pcodeparse.tab.cc"

};
typedef union PCODESTYPE PCODESTYPE;
# define PCODESTYPE_IS_TRIVIAL 1
# define PCODESTYPE_IS_DECLARED 1
#endif


extern PCODESTYPE pcodelval;


int pcodeparse (void);



/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_OP_BOOL_OR = 3,                 /* OP_BOOL_OR  */
  YYSYMBOL_OP_BOOL_AND = 4,                /* OP_BOOL_AND  */
  YYSYMBOL_OP_BOOL_XOR = 5,                /* OP_BOOL_XOR  */
  YYSYMBOL_6_ = 6,                         /* '|'  */
  YYSYMBOL_7_ = 7,                         /* ';'  */
  YYSYMBOL_8_ = 8,                         /* '^'  */
  YYSYMBOL_9_ = 9,                         /* '&'  */
  YYSYMBOL_OP_EQUAL = 10,                  /* OP_EQUAL  */
  YYSYMBOL_OP_NOTEQUAL = 11,               /* OP_NOTEQUAL  */
  YYSYMBOL_OP_FEQUAL = 12,                 /* OP_FEQUAL  */
  YYSYMBOL_OP_FNOTEQUAL = 13,              /* OP_FNOTEQUAL  */
  YYSYMBOL_14_ = 14,                       /* '<'  */
  YYSYMBOL_15_ = 15,                       /* '>'  */
  YYSYMBOL_OP_GREATEQUAL = 16,             /* OP_GREATEQUAL  */
  YYSYMBOL_OP_LESSEQUAL = 17,              /* OP_LESSEQUAL  */
  YYSYMBOL_OP_SLESS = 18,                  /* OP_SLESS  */
  YYSYMBOL_OP_SGREATEQUAL = 19,            /* OP_SGREATEQUAL  */
  YYSYMBOL_OP_SLESSEQUAL = 20,             /* OP_SLESSEQUAL  */
  YYSYMBOL_OP_SGREAT = 21,                 /* OP_SGREAT  */
  YYSYMBOL_OP_FLESS = 22,                  /* OP_FLESS  */
  YYSYMBOL_OP_FGREAT = 23,                 /* OP_FGREAT  */
  YYSYMBOL_OP_FLESSEQUAL = 24,             /* OP_FLESSEQUAL  */
  YYSYMBOL_OP_FGREATEQUAL = 25,            /* OP_FGREATEQUAL  */
  YYSYMBOL_OP_LEFT = 26,                   /* OP_LEFT  */
  YYSYMBOL_OP_RIGHT = 27,                  /* OP_RIGHT  */
  YYSYMBOL_OP_SRIGHT = 28,                 /* OP_SRIGHT  */
  YYSYMBOL_29_ = 29,                       /* '+'  */
  YYSYMBOL_30_ = 30,                       /* '-'  */
  YYSYMBOL_OP_FADD = 31,                   /* OP_FADD  */
  YYSYMBOL_OP_FSUB = 32,                   /* OP_FSUB  */
  YYSYMBOL_33_ = 33,                       /* '*'  */
  YYSYMBOL_34_ = 34,                       /* '/'  */
  YYSYMBOL_35_ = 35,                       /* '%'  */
  YYSYMBOL_OP_SDIV = 36,                   /* OP_SDIV  */
  YYSYMBOL_OP_SREM = 37,                   /* OP_SREM  */
  YYSYMBOL_OP_FMULT = 38,                  /* OP_FMULT  */
  YYSYMBOL_OP_FDIV = 39,                   /* OP_FDIV  */
  YYSYMBOL_40_ = 40,                       /* '!'  */
  YYSYMBOL_41_ = 41,                       /* '~'  */
  YYSYMBOL_OP_ZEXT = 42,                   /* OP_ZEXT  */
  YYSYMBOL_OP_CARRY = 43,                  /* OP_CARRY  */
  YYSYMBOL_OP_BORROW = 44,                 /* OP_BORROW  */
  YYSYMBOL_OP_SEXT = 45,                   /* OP_SEXT  */
  YYSYMBOL_OP_SCARRY = 46,                 /* OP_SCARRY  */
  YYSYMBOL_OP_SBORROW = 47,                /* OP_SBORROW  */
  YYSYMBOL_OP_NAN = 48,                    /* OP_NAN  */
  YYSYMBOL_OP_ABS = 49,                    /* OP_ABS  */
  YYSYMBOL_OP_SQRT = 50,                   /* OP_SQRT  */
  YYSYMBOL_OP_CEIL = 51,                   /* OP_CEIL  */
  YYSYMBOL_OP_FLOOR = 52,                  /* OP_FLOOR  */
  YYSYMBOL_OP_ROUND = 53,                  /* OP_ROUND  */
  YYSYMBOL_OP_INT2FLOAT = 54,              /* OP_INT2FLOAT  */
  YYSYMBOL_OP_FLOAT2FLOAT = 55,            /* OP_FLOAT2FLOAT  */
  YYSYMBOL_OP_TRUNC = 56,                  /* OP_TRUNC  */
  YYSYMBOL_OP_NEW = 57,                    /* OP_NEW  */
  YYSYMBOL_BADINTEGER = 58,                /* BADINTEGER  */
  YYSYMBOL_GOTO_KEY = 59,                  /* GOTO_KEY  */
  YYSYMBOL_CALL_KEY = 60,                  /* CALL_KEY  */
  YYSYMBOL_RETURN_KEY = 61,                /* RETURN_KEY  */
  YYSYMBOL_IF_KEY = 62,                    /* IF_KEY  */
  YYSYMBOL_ENDOFSTREAM = 63,               /* ENDOFSTREAM  */
  YYSYMBOL_LOCAL_KEY = 64,                 /* LOCAL_KEY  */
  YYSYMBOL_INTEGER = 65,                   /* INTEGER  */
  YYSYMBOL_STRING = 66,                    /* STRING  */
  YYSYMBOL_SPACESYM = 67,                  /* SPACESYM  */
  YYSYMBOL_USEROPSYM = 68,                 /* USEROPSYM  */
  YYSYMBOL_VARSYM = 69,                    /* VARSYM  */
  YYSYMBOL_OPERANDSYM = 70,                /* OPERANDSYM  */
  YYSYMBOL_STARTSYM = 71,                  /* STARTSYM  */
  YYSYMBOL_ENDSYM = 72,                    /* ENDSYM  */
  YYSYMBOL_NEXT2SYM = 73,                  /* NEXT2SYM  */
  YYSYMBOL_LABELSYM = 74,                  /* LABELSYM  */
  YYSYMBOL_75_ = 75,                       /* ':'  */
  YYSYMBOL_76_ = 76,                       /* '='  */
  YYSYMBOL_77_ = 77,                       /* '('  */
  YYSYMBOL_78_ = 78,                       /* ')'  */
  YYSYMBOL_79_ = 79,                       /* '['  */
  YYSYMBOL_80_ = 80,                       /* ','  */
  YYSYMBOL_81_ = 81,                       /* ']'  */
  YYSYMBOL_YYACCEPT = 82,                  /* $accept  */
  YYSYMBOL_rtl = 83,                       /* rtl  */
  YYSYMBOL_rtlmid = 84,                    /* rtlmid  */
  YYSYMBOL_statement = 85,                 /* statement  */
  YYSYMBOL_expr = 86,                      /* expr  */
  YYSYMBOL_sizedstar = 87,                 /* sizedstar  */
  YYSYMBOL_jumpdest = 88,                  /* jumpdest  */
  YYSYMBOL_varnode = 89,                   /* varnode  */
  YYSYMBOL_integervarnode = 90,            /* integervarnode  */
  YYSYMBOL_lhsvarnode = 91,                /* lhsvarnode  */
  YYSYMBOL_label = 92,                     /* label  */
  YYSYMBOL_specificsymbol = 93,            /* specificsymbol  */
  YYSYMBOL_paramlist = 94                  /* paramlist  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined PCODESTYPE_IS_TRIVIAL && PCODESTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   1968

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  82
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  13
/* YYNRULES -- Number of rules.  */
#define YYNRULES  120
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  298

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   316


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    40,     2,     2,     2,    35,     9,     2,
      77,    78,    33,    29,    80,    30,     2,    34,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    75,     7,
      14,    76,    15,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    79,     2,    81,     8,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     6,     2,    41,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,    10,    11,    12,    13,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    31,    32,
      36,    37,    38,    39,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,    73,    74
};

#if PCODEDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint8 yyrline[] =
{
       0,   104,   104,   106,   107,   108,   109,   111,   112,   113,
     114,   115,   116,   117,   118,   119,   120,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   195,
     196,   197,   198,   200,   201,   202,   203,   204,   205,   206,
     207,   209,   210,   211,   213,   214,   215,   216,   217,   219,
     220,   222,   223,   225,   226,   227,   228,   229,   231,   232,
     233
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if PCODEDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "OP_BOOL_OR",
  "OP_BOOL_AND", "OP_BOOL_XOR", "'|'", "';'", "'^'", "'&'", "OP_EQUAL",
  "OP_NOTEQUAL", "OP_FEQUAL", "OP_FNOTEQUAL", "'<'", "'>'",
  "OP_GREATEQUAL", "OP_LESSEQUAL", "OP_SLESS", "OP_SGREATEQUAL",
  "OP_SLESSEQUAL", "OP_SGREAT", "OP_FLESS", "OP_FGREAT", "OP_FLESSEQUAL",
  "OP_FGREATEQUAL", "OP_LEFT", "OP_RIGHT", "OP_SRIGHT", "'+'", "'-'",
  "OP_FADD", "OP_FSUB", "'*'", "'/'", "'%'", "OP_SDIV", "OP_SREM",
  "OP_FMULT", "OP_FDIV", "'!'", "'~'", "OP_ZEXT", "OP_CARRY", "OP_BORROW",
  "OP_SEXT", "OP_SCARRY", "OP_SBORROW", "OP_NAN", "OP_ABS", "OP_SQRT",
  "OP_CEIL", "OP_FLOOR", "OP_ROUND", "OP_INT2FLOAT", "OP_FLOAT2FLOAT",
  "OP_TRUNC", "OP_NEW", "BADINTEGER", "GOTO_KEY", "CALL_KEY", "RETURN_KEY",
  "IF_KEY", "ENDOFSTREAM", "LOCAL_KEY", "INTEGER", "STRING", "SPACESYM",
  "USEROPSYM", "VARSYM", "OPERANDSYM", "STARTSYM", "ENDSYM", "NEXT2SYM",
  "LABELSYM", "':'", "'='", "'('", "')'", "'['", "','", "']'", "$accept",
  "rtl", "rtlmid", "statement", "expr", "sizedstar", "jumpdest", "varnode",
  "integervarnode", "lhsvarnode", "label", "specificsymbol", "paramlist", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-68)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-111)

#define yytable_value_is_error(Yyn) \
  ((Yyn) == YYTABLE_NINF)

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -68,     9,  1480,   -68,   459,   -40,   -46,   -68,   564,   672,
      -1,  1430,   -68,   -23,   -45,   -48,   -41,   -68,   -68,   -68,
     -68,   -68,   -68,  1430,   -67,   -68,   -22,   -68,   -12,   -68,
     -28,   -68,   -68,    29,    30,   -13,    -5,   -68,    -7,   -68,
     -68,   -68,   -68,  1430,    58,   -68,  1430,    59,   -68,  1430,
    1430,  1430,  1430,  1430,    -3,     5,     8,    11,    12,    28,
      66,    67,    68,    70,    71,    72,    74,    75,   117,   151,
    1430,  1551,  1430,   -68,   -24,     4,    -6,    10,    16,  1430,
    1430,  1398,    19,    41,  1430,   164,   785,   -68,   -68,   -68,
      -4,   172,   150,   -68,   187,   -68,   277,   -68,   -68,   -68,
     -68,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,   534,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,  1430,
    1430,  1430,  1430,  1430,   888,   -68,   175,    -2,   176,   -68,
     178,  1430,   -68,   -68,   170,  1608,  1867,   -20,  1430,   171,
     173,  1645,   168,   -68,   174,   169,    69,   245,   246,   571,
     351,   642,   424,   461,   679,   750,   787,   858,   895,   966,
    1003,  1074,  1111,   314,    -9,   -68,  1903,   387,   387,  1037,
    1144,  1251,  1355,  1355,  1355,  1355,  1929,  1929,  1929,  1929,
    1929,  1929,  1929,  1929,  1929,  1929,  1929,  1929,   -14,   -14,
     -14,   199,   199,   199,   199,   -68,   -68,   -68,   -68,   -68,
     -68,   -68,   247,   -68,   177,   179,     7,  1682,  1430,   -68,
     250,  1430,  1719,   -68,   -68,   -68,   193,   195,   -68,   -68,
     -68,   -68,   -68,  1430,   -68,  1430,  1430,   -68,   -68,   -68,
     -68,   -68,   -68,   -68,   -68,   -68,   -68,  1430,   -68,   -68,
     -68,   196,   -68,  1430,   -68,  1756,   -68,  1867,   -68,   182,
     -68,  1182,  1219,  1290,  1327,   183,  1793,   -68,   189,   -68,
     -68,   -68,   -68,   -68,   -68,  1430,  1830,   -68
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       3,     0,     0,     1,     0,     0,    92,   105,     0,     0,
       0,     0,     2,     0,   104,   103,     0,   113,   114,   115,
     116,   117,     4,     0,     0,   102,     0,    25,   101,   103,
       0,   107,   101,     0,     0,     0,     0,    97,    96,   100,
      93,    94,    95,     0,     0,    99,     0,     0,    23,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    26,   101,     0,     0,     0,     0,     0,
     118,     0,     0,     0,     0,     0,     0,   112,   111,    91,
       0,     0,     0,    18,     0,    21,     0,    41,    68,    54,
      42,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   118,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    27,     0,     0,     0,     5,
       0,     0,    12,   106,     0,     0,   119,     0,     0,     0,
       0,     0,     0,   108,    90,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    28,    57,    56,    55,    45,
      43,    44,    31,    32,    58,    59,    33,    36,    34,    35,
      37,    38,    39,    40,    60,    61,    62,    63,    46,    47,
      48,    29,    30,    64,    65,    49,    50,    52,    51,    53,
      66,    67,     0,    86,     0,     0,     0,     0,     0,     9,
       0,     0,     0,    16,    17,     7,     0,     0,    98,    20,
      22,    24,    72,     0,    71,     0,     0,    78,    69,    70,
      80,    81,    82,    77,    76,    79,    83,     0,    88,    19,
      85,     0,     6,     0,     8,     0,    14,   120,    13,     0,
      89,     0,     0,     0,     0,     0,     0,    11,     0,    73,
      74,    75,    84,    87,    10,     0,     0,    15
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
     -68,   -68,   -68,   -68,   -11,   264,    -8,     1,   110,   -68,
     267,     0,   154
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     1,     2,    22,   166,    72,    44,    73,    25,    26,
      45,    74,   167
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      71,    47,    28,    24,    32,    31,    48,     4,    82,     3,
      83,   159,    81,    76,   272,   143,   144,   145,   146,   147,
     148,   149,   150,   151,   152,   153,    33,    78,    79,    35,
      77,  -110,    92,    36,    34,    94,    80,    86,    96,    97,
      98,    99,   100,    75,    87,    88,    17,    18,    19,    20,
      21,   156,    89,   157,    84,   158,     7,    85,   240,   117,
     241,   155,    90,    14,  -109,    93,    95,  -109,   165,   268,
     162,   241,    91,   171,   101,   163,   249,   174,    49,   160,
     161,   164,   102,   273,   169,   103,    32,   173,   104,   105,
     179,   180,   181,   182,   183,   184,   185,   186,   187,   188,
     189,   190,   191,   192,   193,   106,   170,   196,   197,   198,
     199,   200,   201,   202,   203,   204,   205,   206,   207,   208,
     209,   210,   211,   212,   213,   214,   215,   216,   217,   218,
     219,   220,   221,   222,   223,   224,   225,   226,   227,   228,
     229,   230,   231,   107,   108,   109,   232,   110,   111,   112,
     237,   113,   114,   118,   119,   120,   121,   242,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,   115,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   275,   116,   172,
     277,   176,   147,   148,   149,   150,   151,   152,   153,   175,
     233,   235,   281,   236,   282,   283,   238,   243,   246,   247,
     248,   244,   250,   251,   269,   270,   284,   276,   279,   271,
     280,   285,   286,   288,   293,   295,    23,   234,   177,    27,
     194,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     118,   119,   120,   121,   296,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   118,   119,   120,
     121,     0,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,   178,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,   266,   121,   267,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   118,   119,   120,
     121,   253,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,     4,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,     0,     0,   255,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     7,     0,     0,
       0,     0,     0,     0,    14,    29,     0,     0,    17,    18,
      19,    20,    21,     0,    30,     0,     0,   118,   119,   120,
     121,   256,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,     5,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,   195,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    37,     0,     0,     0,     0,     0,     0,    38,
      39,     0,     0,     0,     0,    40,    41,    42,     0,     0,
       0,     0,     0,    43,     0,   118,   119,   120,   121,   252,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   143,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   118,   119,   120,   121,     5,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,     0,
     254,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      37,     0,     0,     0,     0,     0,     0,    38,    39,     0,
       0,     0,     0,    40,    41,    42,     0,     0,     0,     0,
       0,    46,     0,   118,   119,   120,   121,   257,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,     4,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,     0,   258,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     7,     0,     0,     0,     0,     0,     0,
      14,    29,     0,     0,    17,    18,    19,    20,    21,     0,
       0,   118,   119,   120,   121,   259,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,   149,   150,   151,   152,   153,   118,   119,
     120,   121,     5,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,     0,   260,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    37,     0,     0,     0,
       0,     0,     0,    38,    39,     0,     0,     0,     0,    40,
      41,    42,     0,     0,     0,     0,     0,     0,     0,   118,
     119,   120,   121,   261,   122,   123,   124,   125,   126,   127,
     128,   129,   130,   131,   132,   133,   134,   135,   136,   137,
     138,   139,   140,   141,   142,   143,   144,   145,   146,   147,
     148,   149,   150,   151,   152,   153,   118,   119,   120,   121,
       0,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,     0,   262,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   118,   119,   120,
     121,   263,   122,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,   118,   119,   120,   121,     0,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,   264,   123,   124,   125,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   135,   136,   137,   138,   139,
     140,   141,   142,   143,   144,   145,   146,   147,   148,   149,
     150,   151,   152,   153,     0,   118,   119,   120,   121,   265,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   143,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   118,   119,   120,   121,     0,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,     0,
     289,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,     0,   118,   119,   120,   121,   290,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,     0,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,     0,   291,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,     0,     0,     0,     0,     0,
       0,   118,   119,   120,   121,   292,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,   149,   150,   151,   152,   153,     0,     4,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      50,     0,    51,     6,     0,     0,     0,     0,     0,     0,
      52,    53,    54,    55,   168,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,     7,     4,
       0,     0,     0,     0,     5,    14,    29,     0,    69,    17,
      18,    19,    20,    21,     0,     0,     0,    70,     0,     0,
       0,     0,     0,     6,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     7,     8,
       9,    10,    11,    12,    13,    14,    15,     0,    16,    17,
      18,    19,    20,    21,   118,   119,   120,   121,     0,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
     143,   144,   145,   146,   147,   148,   149,   150,   151,   152,
     153,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     154,   118,   119,   120,   121,   239,   122,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   132,   133,   134,   135,
     136,   137,   138,   139,   140,   141,   142,   143,   144,   145,
     146,   147,   148,   149,   150,   151,   152,   153,   118,   119,
     120,   121,   245,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,   118,   119,   120,   121,   274,
     122,   123,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   141,
     142,   143,   144,   145,   146,   147,   148,   149,   150,   151,
     152,   153,   118,   119,   120,   121,   278,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   118,
     119,   120,   121,   287,   122,   123,   124,   125,   126,   127,
     128,   129,   130,   131,   132,   133,   134,   135,   136,   137,
     138,   139,   140,   141,   142,   143,   144,   145,   146,   147,
     148,   149,   150,   151,   152,   153,   118,   119,   120,   121,
     294,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,   118,   119,   120,   121,   297,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     118,   119,   120,   121,     0,   122,   123,   124,   125,   126,
     127,   128,   129,   130,   131,   132,   133,   134,   135,   136,
     137,   138,   139,   140,   141,   142,   143,   144,   145,   146,
     147,   148,   149,   150,   151,   152,   153,   119,   120,   121,
       0,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,  -111,  -111,  -111,  -111,  -111,  -111,  -111,
    -111,  -111,  -111,  -111,  -111,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153
};

static const yytype_int16 yycheck[] =
{
      11,     9,     2,     2,     4,     4,     7,     9,    75,     0,
      77,     7,    23,    13,     7,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    66,    75,    76,    75,
      75,    79,    43,    79,    74,    46,    77,    65,    49,    50,
      51,    52,    53,    66,    15,    15,    69,    70,    71,    72,
      73,    75,    65,    77,    76,    79,    58,    79,    78,    70,
      80,    72,    67,    65,    76,     7,     7,    79,    79,    78,
      76,    80,    79,    84,    77,    65,     7,    81,    79,    75,
      76,    65,    77,    76,    65,    77,    86,    86,    77,    77,
     101,   102,   103,   104,   105,   106,   107,   108,   109,   110,
     111,   112,   113,   114,   115,    77,    65,   118,   119,   120,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,    77,    77,    77,   154,    77,    77,    77,
     161,    77,    77,     3,     4,     5,     6,   168,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,    77,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,   238,    77,    65,
     241,    81,    33,    34,    35,    36,    37,    38,    39,    67,
      65,    65,   253,    65,   255,   256,    76,    76,    80,    75,
      81,    78,     7,     7,     7,    78,   267,     7,    65,    80,
      65,    65,   273,    81,    81,    76,     2,   157,    81,     2,
     116,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
       3,     4,     5,     6,   295,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     3,     4,     5,
       6,    -1,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,    81,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    78,     6,    80,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     3,     4,     5,
       6,    80,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,     9,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    -1,    -1,    80,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    58,    -1,    -1,
      -1,    -1,    -1,    -1,    65,    66,    -1,    -1,    69,    70,
      71,    72,    73,    -1,    75,    -1,    -1,     3,     4,     5,
       6,    80,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,    14,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    78,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    58,    -1,    -1,    -1,    -1,    -1,    -1,    65,
      66,    -1,    -1,    -1,    -1,    71,    72,    73,    -1,    -1,
      -1,    -1,    -1,    79,    -1,     3,     4,     5,     6,    78,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,     3,     4,     5,     6,    14,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    -1,
      78,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      58,    -1,    -1,    -1,    -1,    -1,    -1,    65,    66,    -1,
      -1,    -1,    -1,    71,    72,    73,    -1,    -1,    -1,    -1,
      -1,    79,    -1,     3,     4,     5,     6,    78,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,     9,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    -1,    78,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    58,    -1,    -1,    -1,    -1,    -1,    -1,
      65,    66,    -1,    -1,    69,    70,    71,    72,    73,    -1,
      -1,     3,     4,     5,     6,    78,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,     3,     4,
       5,     6,    14,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    -1,    78,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    58,    -1,    -1,    -1,
      -1,    -1,    -1,    65,    66,    -1,    -1,    -1,    -1,    71,
      72,    73,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     3,
       4,     5,     6,    78,     8,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,     3,     4,     5,     6,
      -1,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    -1,    78,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     3,     4,     5,
       6,    78,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,     3,     4,     5,     6,    -1,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    78,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    -1,     3,     4,     5,     6,    78,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,     3,     4,     5,     6,    -1,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    -1,
      78,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    -1,     3,     4,     5,     6,    78,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,    -1,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    -1,    78,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    -1,    -1,    -1,    -1,    -1,
      -1,     3,     4,     5,     6,    78,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    -1,     9,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      30,    -1,    32,    33,    -1,    -1,    -1,    -1,    -1,    -1,
      40,    41,    42,    43,    76,    45,    46,    47,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,     9,
      -1,    -1,    -1,    -1,    14,    65,    66,    -1,    68,    69,
      70,    71,    72,    73,    -1,    -1,    -1,    77,    -1,    -1,
      -1,    -1,    -1,    33,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    58,    59,
      60,    61,    62,    63,    64,    65,    66,    -1,    68,    69,
      70,    71,    72,    73,     3,     4,     5,     6,    -1,     8,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      59,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,     3,     4,     5,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,     3,     4,     5,     6,
       7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
       3,     4,     5,     6,    -1,     8,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,     4,     5,     6,
      -1,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    83,    84,     0,     9,    14,    33,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    68,    69,    70,    71,
      72,    73,    85,    87,    89,    90,    91,    92,    93,    66,
      75,    89,    93,    66,    74,    75,    79,    58,    65,    66,
      71,    72,    73,    79,    88,    92,    79,    88,     7,    79,
      30,    32,    40,    41,    42,    43,    45,    46,    47,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    68,
      77,    86,    87,    89,    93,    66,    93,    75,    75,    76,
      77,    86,    75,    77,    76,    79,    65,    15,    15,    65,
      67,    79,    86,     7,    86,     7,    86,    86,    86,    86,
      86,    77,    77,    77,    77,    77,    77,    77,    77,    77,
      77,    77,    77,    77,    77,    77,    77,    86,     3,     4,
       5,     6,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    59,    86,    75,    77,    79,     7,
      75,    76,    76,    65,    65,    86,    86,    94,    76,    65,
      65,    86,    65,    89,    81,    67,    81,    81,    81,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    94,    78,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    88,    65,    90,    65,    65,    86,    76,     7,
      78,    80,    86,    76,    78,     7,    80,    75,    81,     7,
       7,     7,    78,    80,    78,    80,    80,    78,    78,    78,
      78,    78,    78,    78,    78,    78,    78,    80,    78,     7,
      78,    80,     7,    76,     7,    86,     7,    86,     7,    65,
      65,    86,    86,    86,    86,    65,    86,     7,    81,    78,
      78,    78,    78,    81,     7,    76,    86,     7
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    82,    83,    84,    84,    84,    84,    85,    85,    85,
      85,    85,    85,    85,    85,    85,    85,    85,    85,    85,
      85,    85,    85,    85,    85,    85,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    86,    86,    87,
      87,    87,    87,    88,    88,    88,    88,    88,    88,    88,
      88,    89,    89,    89,    90,    90,    90,    90,    90,    91,
      91,    92,    92,    93,    93,    93,    93,    93,    94,    94,
      94
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     0,     2,     4,     6,     4,     5,     4,
       7,     6,     3,     5,     5,     9,     4,     4,     3,     5,
       5,     3,     5,     2,     5,     1,     1,     2,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     2,     2,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     2,     4,
       4,     4,     4,     6,     6,     6,     4,     4,     4,     4,
       4,     4,     4,     4,     6,     4,     3,     6,     4,     6,
       4,     3,     1,     1,     1,     1,     1,     1,     4,     1,
       1,     1,     1,     1,     1,     1,     3,     2,     4,     1,
       1,     3,     3,     1,     1,     1,     1,     1,     0,     1,
       3
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = PCODEEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == PCODEEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use PCODEerror or PCODEUNDEF. */
#define YYERRCODE PCODEUNDEF


/* Enable debugging if requested.  */
#if PCODEDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !PCODEDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !PCODEDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL_INTEGER: /* INTEGER  */
#line 94 "pcodeparse.y"
            { delete ((*yyvaluep).i); }
#line 1563 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_STRING: /* STRING  */
#line 95 "pcodeparse.y"
            { delete ((*yyvaluep).str); }
#line 1569 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_rtlmid: /* rtlmid  */
#line 97 "pcodeparse.y"
            { delete ((*yyvaluep).sem); }
#line 1575 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_statement: /* statement  */
#line 98 "pcodeparse.y"
            { if (((*yyvaluep).stmt) != (vector<OpTpl *> *)0) { for(int4 i=0;i<((*yyvaluep).stmt)->size();++i) delete (*((*yyvaluep).stmt))[i]; delete ((*yyvaluep).stmt);} }
#line 1581 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_expr: /* expr  */
#line 99 "pcodeparse.y"
            { delete ((*yyvaluep).tree); }
#line 1587 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_sizedstar: /* sizedstar  */
#line 101 "pcodeparse.y"
            { delete ((*yyvaluep).starqual); }
#line 1593 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_jumpdest: /* jumpdest  */
#line 100 "pcodeparse.y"
            { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }
#line 1599 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_varnode: /* varnode  */
#line 100 "pcodeparse.y"
            { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }
#line 1605 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_integervarnode: /* integervarnode  */
#line 100 "pcodeparse.y"
            { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }
#line 1611 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_lhsvarnode: /* lhsvarnode  */
#line 100 "pcodeparse.y"
            { if (((*yyvaluep).varnode) != (VarnodeTpl *)0) delete ((*yyvaluep).varnode); }
#line 1617 "pcodeparse.tab.cc"
        break;

    case YYSYMBOL_paramlist: /* paramlist  */
#line 96 "pcodeparse.y"
            { for(int4 i=0;i<((*yyvaluep).param)->size();++i) delete (*((*yyvaluep).param))[i]; delete ((*yyvaluep).param); }
#line 1623 "pcodeparse.tab.cc"
        break;

      default:
        break;
    }
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = PCODEEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == PCODEEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= PCODEEOF)
    {
      yychar = PCODEEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == PCODEerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = PCODEUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = PCODEEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* rtl: rtlmid ENDOFSTREAM  */
#line 104 "pcodeparse.y"
                                        { pcode->setResult((yyvsp[-1].sem)); }
#line 1893 "pcodeparse.tab.cc"
    break;

  case 3: /* rtlmid: %empty  */
#line 106 "pcodeparse.y"
                                        { (yyval.sem) = new ConstructTpl(); }
#line 1899 "pcodeparse.tab.cc"
    break;

  case 4: /* rtlmid: rtlmid statement  */
#line 107 "pcodeparse.y"
                                        { (yyval.sem) = (yyvsp[-1].sem); if (!(yyval.sem)->addOpList(*(yyvsp[0].stmt))) { delete (yyvsp[0].stmt); yyerror("Multiple delayslot declarations"); YYERROR; } delete (yyvsp[0].stmt); }
#line 1905 "pcodeparse.tab.cc"
    break;

  case 5: /* rtlmid: rtlmid LOCAL_KEY STRING ';'  */
#line 108 "pcodeparse.y"
                                { (yyval.sem) = (yyvsp[-3].sem); pcode->newLocalDefinition((yyvsp[-1].str)); }
#line 1911 "pcodeparse.tab.cc"
    break;

  case 6: /* rtlmid: rtlmid LOCAL_KEY STRING ':' INTEGER ';'  */
#line 109 "pcodeparse.y"
                                            { (yyval.sem) = (yyvsp[-5].sem); pcode->newLocalDefinition((yyvsp[-3].str),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 1917 "pcodeparse.tab.cc"
    break;

  case 7: /* statement: lhsvarnode '=' expr ';'  */
#line 111 "pcodeparse.y"
                                        { (yyvsp[-1].tree)->setOutput((yyvsp[-3].varnode)); (yyval.stmt) = ExprTree::toVector((yyvsp[-1].tree)); }
#line 1923 "pcodeparse.tab.cc"
    break;

  case 8: /* statement: LOCAL_KEY STRING '=' expr ';'  */
#line 112 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->newOutput(true,(yyvsp[-1].tree),(yyvsp[-3].str)); }
#line 1929 "pcodeparse.tab.cc"
    break;

  case 9: /* statement: STRING '=' expr ';'  */
#line 113 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->newOutput(false,(yyvsp[-1].tree),(yyvsp[-3].str)); }
#line 1935 "pcodeparse.tab.cc"
    break;

  case 10: /* statement: LOCAL_KEY STRING ':' INTEGER '=' expr ';'  */
#line 114 "pcodeparse.y"
                                                { (yyval.stmt) = pcode->newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
#line 1941 "pcodeparse.tab.cc"
    break;

  case 11: /* statement: STRING ':' INTEGER '=' expr ';'  */
#line 115 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->newOutput(true,(yyvsp[-1].tree),(yyvsp[-5].str),*(yyvsp[-3].i)); delete (yyvsp[-3].i); }
#line 1947 "pcodeparse.tab.cc"
    break;

  case 12: /* statement: LOCAL_KEY specificsymbol '='  */
#line 116 "pcodeparse.y"
                                 { (yyval.stmt) = (vector<OpTpl *> *)0; string errmsg = "Redefinition of symbol: "+(yyvsp[-1].specsym)->getName(); yyerror(errmsg.c_str()); YYERROR; }
#line 1953 "pcodeparse.tab.cc"
    break;

  case 13: /* statement: sizedstar expr '=' expr ';'  */
#line 117 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createStore((yyvsp[-4].starqual),(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 1959 "pcodeparse.tab.cc"
    break;

  case 14: /* statement: USEROPSYM '(' paramlist ')' ';'  */
#line 118 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createUserOpNoOut((yyvsp[-4].useropsym),(yyvsp[-2].param)); }
#line 1965 "pcodeparse.tab.cc"
    break;

  case 15: /* statement: lhsvarnode '[' INTEGER ',' INTEGER ']' '=' expr ';'  */
#line 119 "pcodeparse.y"
                                                        { (yyval.stmt) = pcode->assignBitRange((yyvsp[-8].varnode),(uint4)*(yyvsp[-6].i),(uint4)*(yyvsp[-4].i),(yyvsp[-1].tree)); delete (yyvsp[-6].i), delete (yyvsp[-4].i); }
#line 1971 "pcodeparse.tab.cc"
    break;

  case 16: /* statement: varnode ':' INTEGER '='  */
#line 120 "pcodeparse.y"
                                        { (yyval.stmt) = (vector<OpTpl *> *)0; delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal truncation on left-hand side of assignment"); YYERROR; }
#line 1977 "pcodeparse.tab.cc"
    break;

  case 17: /* statement: varnode '(' INTEGER ')'  */
#line 121 "pcodeparse.y"
                                        { (yyval.stmt) = (vector<OpTpl *> *)0; delete (yyvsp[-3].varnode); delete (yyvsp[-1].i); yyerror("Illegal subpiece on left-hand side of assignment"); YYERROR; }
#line 1983 "pcodeparse.tab.cc"
    break;

  case 18: /* statement: GOTO_KEY jumpdest ';'  */
#line 122 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createOpNoOut(CPUI_BRANCH,new ExprTree((yyvsp[-1].varnode))); }
#line 1989 "pcodeparse.tab.cc"
    break;

  case 19: /* statement: IF_KEY expr GOTO_KEY jumpdest ';'  */
#line 123 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createOpNoOut(CPUI_CBRANCH,new ExprTree((yyvsp[-1].varnode)),(yyvsp[-3].tree)); }
#line 1995 "pcodeparse.tab.cc"
    break;

  case 20: /* statement: GOTO_KEY '[' expr ']' ';'  */
#line 124 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createOpNoOut(CPUI_BRANCHIND,(yyvsp[-2].tree)); }
#line 2001 "pcodeparse.tab.cc"
    break;

  case 21: /* statement: CALL_KEY jumpdest ';'  */
#line 125 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createOpNoOut(CPUI_CALL,new ExprTree((yyvsp[-1].varnode))); }
#line 2007 "pcodeparse.tab.cc"
    break;

  case 22: /* statement: CALL_KEY '[' expr ']' ';'  */
#line 126 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createOpNoOut(CPUI_CALLIND,(yyvsp[-2].tree)); }
#line 2013 "pcodeparse.tab.cc"
    break;

  case 23: /* statement: RETURN_KEY ';'  */
#line 127 "pcodeparse.y"
                                        { (yyval.stmt) = (vector<OpTpl *> *)0; yyerror("Must specify an indirect parameter for return"); YYERROR; }
#line 2019 "pcodeparse.tab.cc"
    break;

  case 24: /* statement: RETURN_KEY '[' expr ']' ';'  */
#line 128 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->createOpNoOut(CPUI_RETURN,(yyvsp[-2].tree)); }
#line 2025 "pcodeparse.tab.cc"
    break;

  case 25: /* statement: label  */
#line 129 "pcodeparse.y"
                                        { (yyval.stmt) = pcode->placeLabel( (yyvsp[0].labelsym) ); }
#line 2031 "pcodeparse.tab.cc"
    break;

  case 26: /* expr: varnode  */
#line 131 "pcodeparse.y"
              { (yyval.tree) = new ExprTree((yyvsp[0].varnode)); }
#line 2037 "pcodeparse.tab.cc"
    break;

  case 27: /* expr: sizedstar expr  */
#line 132 "pcodeparse.y"
                                { (yyval.tree) = pcode->createLoad((yyvsp[-1].starqual),(yyvsp[0].tree)); }
#line 2043 "pcodeparse.tab.cc"
    break;

  case 28: /* expr: '(' expr ')'  */
#line 133 "pcodeparse.y"
                                { (yyval.tree) = (yyvsp[-1].tree); }
#line 2049 "pcodeparse.tab.cc"
    break;

  case 29: /* expr: expr '+' expr  */
#line 134 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2055 "pcodeparse.tab.cc"
    break;

  case 30: /* expr: expr '-' expr  */
#line 135 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2061 "pcodeparse.tab.cc"
    break;

  case 31: /* expr: expr OP_EQUAL expr  */
#line 136 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2067 "pcodeparse.tab.cc"
    break;

  case 32: /* expr: expr OP_NOTEQUAL expr  */
#line 137 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2073 "pcodeparse.tab.cc"
    break;

  case 33: /* expr: expr '<' expr  */
#line 138 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2079 "pcodeparse.tab.cc"
    break;

  case 34: /* expr: expr OP_GREATEQUAL expr  */
#line 139 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 2085 "pcodeparse.tab.cc"
    break;

  case 35: /* expr: expr OP_LESSEQUAL expr  */
#line 140 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2091 "pcodeparse.tab.cc"
    break;

  case 36: /* expr: expr '>' expr  */
#line 141 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 2097 "pcodeparse.tab.cc"
    break;

  case 37: /* expr: expr OP_SLESS expr  */
#line 142 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SLESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2103 "pcodeparse.tab.cc"
    break;

  case 38: /* expr: expr OP_SGREATEQUAL expr  */
#line 143 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SLESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 2109 "pcodeparse.tab.cc"
    break;

  case 39: /* expr: expr OP_SLESSEQUAL expr  */
#line 144 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SLESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2115 "pcodeparse.tab.cc"
    break;

  case 40: /* expr: expr OP_SGREAT expr  */
#line 145 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SLESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 2121 "pcodeparse.tab.cc"
    break;

  case 41: /* expr: '-' expr  */
#line 146 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_2COMP,(yyvsp[0].tree)); }
#line 2127 "pcodeparse.tab.cc"
    break;

  case 42: /* expr: '~' expr  */
#line 147 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_NEGATE,(yyvsp[0].tree)); }
#line 2133 "pcodeparse.tab.cc"
    break;

  case 43: /* expr: expr '^' expr  */
#line 148 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2139 "pcodeparse.tab.cc"
    break;

  case 44: /* expr: expr '&' expr  */
#line 149 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2145 "pcodeparse.tab.cc"
    break;

  case 45: /* expr: expr '|' expr  */
#line 150 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2151 "pcodeparse.tab.cc"
    break;

  case 46: /* expr: expr OP_LEFT expr  */
#line 151 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_LEFT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2157 "pcodeparse.tab.cc"
    break;

  case 47: /* expr: expr OP_RIGHT expr  */
#line 152 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_RIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2163 "pcodeparse.tab.cc"
    break;

  case 48: /* expr: expr OP_SRIGHT expr  */
#line 153 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SRIGHT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2169 "pcodeparse.tab.cc"
    break;

  case 49: /* expr: expr '*' expr  */
#line 154 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2175 "pcodeparse.tab.cc"
    break;

  case 50: /* expr: expr '/' expr  */
#line 155 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2181 "pcodeparse.tab.cc"
    break;

  case 51: /* expr: expr OP_SDIV expr  */
#line 156 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SDIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2187 "pcodeparse.tab.cc"
    break;

  case 52: /* expr: expr '%' expr  */
#line 157 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_REM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2193 "pcodeparse.tab.cc"
    break;

  case 53: /* expr: expr OP_SREM expr  */
#line 158 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SREM,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2199 "pcodeparse.tab.cc"
    break;

  case 54: /* expr: '!' expr  */
#line 159 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_BOOL_NEGATE,(yyvsp[0].tree)); }
#line 2205 "pcodeparse.tab.cc"
    break;

  case 55: /* expr: expr OP_BOOL_XOR expr  */
#line 160 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_BOOL_XOR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2211 "pcodeparse.tab.cc"
    break;

  case 56: /* expr: expr OP_BOOL_AND expr  */
#line 161 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_BOOL_AND,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2217 "pcodeparse.tab.cc"
    break;

  case 57: /* expr: expr OP_BOOL_OR expr  */
#line 162 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_BOOL_OR,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2223 "pcodeparse.tab.cc"
    break;

  case 58: /* expr: expr OP_FEQUAL expr  */
#line 163 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_EQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2229 "pcodeparse.tab.cc"
    break;

  case 59: /* expr: expr OP_FNOTEQUAL expr  */
#line 164 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_NOTEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2235 "pcodeparse.tab.cc"
    break;

  case 60: /* expr: expr OP_FLESS expr  */
#line 165 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESS,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2241 "pcodeparse.tab.cc"
    break;

  case 61: /* expr: expr OP_FGREAT expr  */
#line 166 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESS,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 2247 "pcodeparse.tab.cc"
    break;

  case 62: /* expr: expr OP_FLESSEQUAL expr  */
#line 167 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2253 "pcodeparse.tab.cc"
    break;

  case 63: /* expr: expr OP_FGREATEQUAL expr  */
#line 168 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_LESSEQUAL,(yyvsp[0].tree),(yyvsp[-2].tree)); }
#line 2259 "pcodeparse.tab.cc"
    break;

  case 64: /* expr: expr OP_FADD expr  */
#line 169 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_ADD,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2265 "pcodeparse.tab.cc"
    break;

  case 65: /* expr: expr OP_FSUB expr  */
#line 170 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_SUB,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2271 "pcodeparse.tab.cc"
    break;

  case 66: /* expr: expr OP_FMULT expr  */
#line 171 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_MULT,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2277 "pcodeparse.tab.cc"
    break;

  case 67: /* expr: expr OP_FDIV expr  */
#line 172 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_DIV,(yyvsp[-2].tree),(yyvsp[0].tree)); }
#line 2283 "pcodeparse.tab.cc"
    break;

  case 68: /* expr: OP_FSUB expr  */
#line 173 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_NEG,(yyvsp[0].tree)); }
#line 2289 "pcodeparse.tab.cc"
    break;

  case 69: /* expr: OP_ABS '(' expr ')'  */
#line 174 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_ABS,(yyvsp[-1].tree)); }
#line 2295 "pcodeparse.tab.cc"
    break;

  case 70: /* expr: OP_SQRT '(' expr ')'  */
#line 175 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_SQRT,(yyvsp[-1].tree)); }
#line 2301 "pcodeparse.tab.cc"
    break;

  case 71: /* expr: OP_SEXT '(' expr ')'  */
#line 176 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_SEXT,(yyvsp[-1].tree)); }
#line 2307 "pcodeparse.tab.cc"
    break;

  case 72: /* expr: OP_ZEXT '(' expr ')'  */
#line 177 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_INT_ZEXT,(yyvsp[-1].tree)); }
#line 2313 "pcodeparse.tab.cc"
    break;

  case 73: /* expr: OP_CARRY '(' expr ',' expr ')'  */
#line 178 "pcodeparse.y"
                                   { (yyval.tree) = pcode->createOp(CPUI_INT_CARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 2319 "pcodeparse.tab.cc"
    break;

  case 74: /* expr: OP_SCARRY '(' expr ',' expr ')'  */
#line 179 "pcodeparse.y"
                                    { (yyval.tree) = pcode->createOp(CPUI_INT_SCARRY,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 2325 "pcodeparse.tab.cc"
    break;

  case 75: /* expr: OP_SBORROW '(' expr ',' expr ')'  */
#line 180 "pcodeparse.y"
                                     { (yyval.tree) = pcode->createOp(CPUI_INT_SBORROW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 2331 "pcodeparse.tab.cc"
    break;

  case 76: /* expr: OP_FLOAT2FLOAT '(' expr ')'  */
#line 181 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_FLOAT2FLOAT,(yyvsp[-1].tree)); }
#line 2337 "pcodeparse.tab.cc"
    break;

  case 77: /* expr: OP_INT2FLOAT '(' expr ')'  */
#line 182 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_INT2FLOAT,(yyvsp[-1].tree)); }
#line 2343 "pcodeparse.tab.cc"
    break;

  case 78: /* expr: OP_NAN '(' expr ')'  */
#line 183 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_NAN,(yyvsp[-1].tree)); }
#line 2349 "pcodeparse.tab.cc"
    break;

  case 79: /* expr: OP_TRUNC '(' expr ')'  */
#line 184 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_TRUNC,(yyvsp[-1].tree)); }
#line 2355 "pcodeparse.tab.cc"
    break;

  case 80: /* expr: OP_CEIL '(' expr ')'  */
#line 185 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_CEIL,(yyvsp[-1].tree)); }
#line 2361 "pcodeparse.tab.cc"
    break;

  case 81: /* expr: OP_FLOOR '(' expr ')'  */
#line 186 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_FLOOR,(yyvsp[-1].tree)); }
#line 2367 "pcodeparse.tab.cc"
    break;

  case 82: /* expr: OP_ROUND '(' expr ')'  */
#line 187 "pcodeparse.y"
                                { (yyval.tree) = pcode->createOp(CPUI_FLOAT_ROUND,(yyvsp[-1].tree)); }
#line 2373 "pcodeparse.tab.cc"
    break;

  case 83: /* expr: OP_NEW '(' expr ')'  */
#line 188 "pcodeparse.y"
                            { (yyval.tree) = pcode->createOp(CPUI_NEW,(yyvsp[-1].tree)); }
#line 2379 "pcodeparse.tab.cc"
    break;

  case 84: /* expr: OP_NEW '(' expr ',' expr ')'  */
#line 189 "pcodeparse.y"
                                 { (yyval.tree) = pcode->createOp(CPUI_NEW,(yyvsp[-3].tree),(yyvsp[-1].tree)); }
#line 2385 "pcodeparse.tab.cc"
    break;

  case 85: /* expr: specificsymbol '(' integervarnode ')'  */
#line 190 "pcodeparse.y"
                                          { (yyval.tree) = pcode->createOp(CPUI_SUBPIECE,new ExprTree((yyvsp[-3].specsym)->getVarnode()),new ExprTree((yyvsp[-1].varnode))); }
#line 2391 "pcodeparse.tab.cc"
    break;

  case 86: /* expr: specificsymbol ':' INTEGER  */
#line 191 "pcodeparse.y"
                                { (yyval.tree) = pcode->createBitRange((yyvsp[-2].specsym),0,(uint4)(*(yyvsp[0].i) * 8)); delete (yyvsp[0].i); }
#line 2397 "pcodeparse.tab.cc"
    break;

  case 87: /* expr: specificsymbol '[' INTEGER ',' INTEGER ']'  */
#line 192 "pcodeparse.y"
                                               { (yyval.tree) = pcode->createBitRange((yyvsp[-5].specsym),(uint4)*(yyvsp[-3].i),(uint4)*(yyvsp[-1].i)); delete (yyvsp[-3].i), delete (yyvsp[-1].i); }
#line 2403 "pcodeparse.tab.cc"
    break;

  case 88: /* expr: USEROPSYM '(' paramlist ')'  */
#line 193 "pcodeparse.y"
                                { (yyval.tree) = pcode->createUserOp((yyvsp[-3].useropsym),(yyvsp[-1].param)); }
#line 2409 "pcodeparse.tab.cc"
    break;

  case 89: /* sizedstar: '*' '[' SPACESYM ']' ':' INTEGER  */
#line 195 "pcodeparse.y"
                                            { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl((yyvsp[-3].spacesym)->getSpace()); }
#line 2415 "pcodeparse.tab.cc"
    break;

  case 90: /* sizedstar: '*' '[' SPACESYM ']'  */
#line 196 "pcodeparse.y"
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl((yyvsp[-1].spacesym)->getSpace()); }
#line 2421 "pcodeparse.tab.cc"
    break;

  case 91: /* sizedstar: '*' ':' INTEGER  */
#line 197 "pcodeparse.y"
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = *(yyvsp[0].i); delete (yyvsp[0].i); (yyval.starqual)->id=ConstTpl(pcode->getDefaultSpace()); }
#line 2427 "pcodeparse.tab.cc"
    break;

  case 92: /* sizedstar: '*'  */
#line 198 "pcodeparse.y"
                                { (yyval.starqual) = new StarQuality; (yyval.starqual)->size = 0; (yyval.starqual)->id=ConstTpl(pcode->getDefaultSpace()); }
#line 2433 "pcodeparse.tab.cc"
    break;

  case 93: /* jumpdest: STARTSYM  */
#line 200 "pcodeparse.y"
                                { VarnodeTpl *sym = (yyvsp[0].startsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 2439 "pcodeparse.tab.cc"
    break;

  case 94: /* jumpdest: ENDSYM  */
#line 201 "pcodeparse.y"
                                { VarnodeTpl *sym = (yyvsp[0].endsym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 2445 "pcodeparse.tab.cc"
    break;

  case 95: /* jumpdest: NEXT2SYM  */
#line 202 "pcodeparse.y"
                        { VarnodeTpl *sym = (yyvsp[0].next2sym)->getVarnode(); (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),sym->getOffset(),ConstTpl(ConstTpl::j_curspace_size)); delete sym; }
#line 2451 "pcodeparse.tab.cc"
    break;

  case 96: /* jumpdest: INTEGER  */
#line 203 "pcodeparse.y"
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::j_curspace_size)); delete (yyvsp[0].i); }
#line 2457 "pcodeparse.tab.cc"
    break;

  case 97: /* jumpdest: BADINTEGER  */
#line 204 "pcodeparse.y"
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(ConstTpl::j_curspace),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::j_curspace_size)); yyerror("Parsed integer is too big (overflow)"); }
#line 2463 "pcodeparse.tab.cc"
    break;

  case 98: /* jumpdest: INTEGER '[' SPACESYM ']'  */
#line 205 "pcodeparse.y"
                                { AddrSpace *spc = (yyvsp[-1].spacesym)->getSpace(); (yyval.varnode) = new VarnodeTpl(ConstTpl(spc),ConstTpl(ConstTpl::real,*(yyvsp[-3].i)),ConstTpl(ConstTpl::real,spc->getAddrSize())); delete (yyvsp[-3].i); }
#line 2469 "pcodeparse.tab.cc"
    break;

  case 99: /* jumpdest: label  */
#line 206 "pcodeparse.y"
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::j_relative,(yyvsp[0].labelsym)->getIndex()),ConstTpl(ConstTpl::real,sizeof(uintm))); (yyvsp[0].labelsym)->incrementRefCount(); }
#line 2475 "pcodeparse.tab.cc"
    break;

  case 100: /* jumpdest: STRING  */
#line 207 "pcodeparse.y"
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown jump destination: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2481 "pcodeparse.tab.cc"
    break;

  case 101: /* varnode: specificsymbol  */
#line 209 "pcodeparse.y"
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 2487 "pcodeparse.tab.cc"
    break;

  case 102: /* varnode: integervarnode  */
#line 210 "pcodeparse.y"
                                { (yyval.varnode) = (yyvsp[0].varnode); }
#line 2493 "pcodeparse.tab.cc"
    break;

  case 103: /* varnode: STRING  */
#line 211 "pcodeparse.y"
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown varnode parameter: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2499 "pcodeparse.tab.cc"
    break;

  case 104: /* integervarnode: INTEGER  */
#line 213 "pcodeparse.y"
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[0].i)),ConstTpl(ConstTpl::real,0)); delete (yyvsp[0].i); }
#line 2505 "pcodeparse.tab.cc"
    break;

  case 105: /* integervarnode: BADINTEGER  */
#line 214 "pcodeparse.y"
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,0),ConstTpl(ConstTpl::real,0)); yyerror("Parsed integer is too big (overflow)"); }
#line 2511 "pcodeparse.tab.cc"
    break;

  case 106: /* integervarnode: INTEGER ':' INTEGER  */
#line 215 "pcodeparse.y"
                                { (yyval.varnode) = new VarnodeTpl(ConstTpl(pcode->getConstantSpace()),ConstTpl(ConstTpl::real,*(yyvsp[-2].i)),ConstTpl(ConstTpl::real,*(yyvsp[0].i))); delete (yyvsp[-2].i); delete (yyvsp[0].i); }
#line 2517 "pcodeparse.tab.cc"
    break;

  case 107: /* integervarnode: '&' varnode  */
#line 216 "pcodeparse.y"
                                { (yyval.varnode) = pcode->addressOf((yyvsp[0].varnode),0); }
#line 2523 "pcodeparse.tab.cc"
    break;

  case 108: /* integervarnode: '&' ':' INTEGER varnode  */
#line 217 "pcodeparse.y"
                                { (yyval.varnode) = pcode->addressOf((yyvsp[0].varnode),*(yyvsp[-1].i)); delete (yyvsp[-1].i); }
#line 2529 "pcodeparse.tab.cc"
    break;

  case 109: /* lhsvarnode: specificsymbol  */
#line 219 "pcodeparse.y"
                                { (yyval.varnode) = (yyvsp[0].specsym)->getVarnode(); }
#line 2535 "pcodeparse.tab.cc"
    break;

  case 110: /* lhsvarnode: STRING  */
#line 220 "pcodeparse.y"
                                { (yyval.varnode) = (VarnodeTpl *)0; string errmsg = "Unknown assignment varnode: "+*(yyvsp[0].str); delete (yyvsp[0].str); yyerror(errmsg.c_str()); YYERROR; }
#line 2541 "pcodeparse.tab.cc"
    break;

  case 111: /* label: '<' LABELSYM '>'  */
#line 222 "pcodeparse.y"
                                { (yyval.labelsym) = (yyvsp[-1].labelsym); }
#line 2547 "pcodeparse.tab.cc"
    break;

  case 112: /* label: '<' STRING '>'  */
#line 223 "pcodeparse.y"
                                { (yyval.labelsym) = pcode->defineLabel( (yyvsp[-1].str) ); }
#line 2553 "pcodeparse.tab.cc"
    break;

  case 113: /* specificsymbol: VARSYM  */
#line 225 "pcodeparse.y"
                                { (yyval.specsym) = (yyvsp[0].varsym); }
#line 2559 "pcodeparse.tab.cc"
    break;

  case 114: /* specificsymbol: OPERANDSYM  */
#line 226 "pcodeparse.y"
                                { (yyval.specsym) = (yyvsp[0].operandsym); }
#line 2565 "pcodeparse.tab.cc"
    break;

  case 115: /* specificsymbol: STARTSYM  */
#line 227 "pcodeparse.y"
                                { (yyval.specsym) = (yyvsp[0].startsym); }
#line 2571 "pcodeparse.tab.cc"
    break;

  case 116: /* specificsymbol: ENDSYM  */
#line 228 "pcodeparse.y"
                                { (yyval.specsym) = (yyvsp[0].endsym); }
#line 2577 "pcodeparse.tab.cc"
    break;

  case 117: /* specificsymbol: NEXT2SYM  */
#line 229 "pcodeparse.y"
                                { (yyval.specsym) = (yyvsp[0].next2sym); }
#line 2583 "pcodeparse.tab.cc"
    break;

  case 118: /* paramlist: %empty  */
#line 231 "pcodeparse.y"
                                { (yyval.param) = new vector<ExprTree *>; }
#line 2589 "pcodeparse.tab.cc"
    break;

  case 119: /* paramlist: expr  */
#line 232 "pcodeparse.y"
                                { (yyval.param) = new vector<ExprTree *>; (yyval.param)->push_back((yyvsp[0].tree)); }
#line 2595 "pcodeparse.tab.cc"
    break;

  case 120: /* paramlist: paramlist ',' expr  */
#line 233 "pcodeparse.y"
                                { (yyval.param) = (yyvsp[-2].param); (yyval.param)->push_back((yyvsp[0].tree)); }
#line 2601 "pcodeparse.tab.cc"
    break;


#line 2605 "pcodeparse.tab.cc"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == PCODEEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= PCODEEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == PCODEEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = PCODEEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != PCODEEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 235 "pcodeparse.y"


#define IDENTREC_SIZE 46
const IdentRec PcodeLexer::idents[]= { // Sorted list of identifiers
  { "!=", OP_NOTEQUAL },
  { "&&", OP_BOOL_AND },
  { "<<", OP_LEFT },
  { "<=", OP_LESSEQUAL },
  { "==", OP_EQUAL },
  { ">=", OP_GREATEQUAL },
  { ">>", OP_RIGHT },
  { "^^", OP_BOOL_XOR },
  { "||", OP_BOOL_OR },
  { "abs", OP_ABS },
  { "borrow", OP_BORROW },
  { "call", CALL_KEY },
  { "carry", OP_CARRY },
  { "ceil", OP_CEIL },
  { "f!=", OP_FNOTEQUAL },
  { "f*", OP_FMULT },
  { "f+", OP_FADD },
  { "f-", OP_FSUB },
  { "f/", OP_FDIV },
  { "f<", OP_FLESS },
  { "f<=", OP_FLESSEQUAL },
  { "f==", OP_FEQUAL },
  { "f>", OP_FGREAT },
  { "f>=", OP_FGREATEQUAL },
  { "float2float", OP_FLOAT2FLOAT },
  { "floor", OP_FLOOR },
  { "goto", GOTO_KEY },
  { "if", IF_KEY },
  { "int2float", OP_INT2FLOAT },
  { "local", LOCAL_KEY },
  { "nan", OP_NAN },
  { "return", RETURN_KEY },
  { "round", OP_ROUND },
  { "s%", OP_SREM },
  { "s/", OP_SDIV },
  { "s<", OP_SLESS },
  { "s<=", OP_SLESSEQUAL },
  { "s>", OP_SGREAT },
  { "s>=", OP_SGREATEQUAL },
  { "s>>",OP_SRIGHT },
  { "sborrow", OP_SBORROW },
  { "scarry", OP_SCARRY },
  { "sext", OP_SEXT },
  { "sqrt", OP_SQRT },
  { "trunc", OP_TRUNC },
  { "zext", OP_ZEXT }
};

int4 PcodeLexer::findIdentifier(const string &str) const

{
  int4 low = 0;
  int4 high = IDENTREC_SIZE-1;
  int4 comp;
  do {
    int4 targ = (low+high)/2;
    comp = str.compare(idents[targ].nm);
    if (comp < 0) 		// str comes before targ
      high = targ-1;
    else if (comp > 0)		// str comes after targ
      low = targ + 1;
    else
      return targ;
  } while(low <= high);
  return -1;
}

int4 PcodeLexer::moveState(void)

{
  switch(curstate) {
  case start:
    switch(curchar) {
    case '#':
      curstate = comment;
      return start;
    case '|':
      if (lookahead1 == '|') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '&':
      if (lookahead1 == '&') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '^':
      if (lookahead1 == '^') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '>':
      if ((lookahead1 == '>')||(lookahead1=='=')) {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '<':
      if ((lookahead1 == '<')||(lookahead1=='=')) {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '=':
      if (lookahead1 == '=') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '!':
      if (lookahead1 == '=') {
	starttoken();
	curstate = special2;
	return start;
      }
      return punctuation;
    case '(':
    case ')':
    case ',':
    case ':':
    case '[':
    case ']':
    case ';':
    case '+':
    case '-':
    case '*':
    case '/':
    case '%':
    case '~':
      return punctuation;
    case 's':
    case 'f':
      if (curchar == 's') {
	if ((lookahead1 == '/')||(lookahead1=='%')) {
	  starttoken();
	  curstate = special2;
	  return start;
	}
	else if (lookahead1 == '<') {
	  starttoken();
	  if (lookahead2 == '=')
	    curstate = special3;
	  else
	    curstate = special2;
	  return start;
	}
	else if (lookahead1 == '>') {
	  starttoken();
	  if ((lookahead2=='>')||(lookahead2=='='))
	    curstate = special3;
	  else
	    curstate = special2;
	  return start;
	}
      }
      else {			// curchar == 'f'
	if ((lookahead1=='+')||(lookahead1=='-')||(lookahead1=='*')||(lookahead1=='/')) {
	  starttoken();
	  curstate = special2;
	  return start;
	}
	else if (((lookahead1=='=')||(lookahead1=='!'))&&(lookahead2=='=')) {
	  starttoken();
	  curstate = special3;
	  return start;
	}
	else if ((lookahead1=='<')||(lookahead1=='>')) {
	  starttoken();
	  if (lookahead2 == '=')
	    curstate = special3;
	  else
	    curstate = special2;
	  return start;
	}
      }
      // fall through here, treat 's' and 'f' as ordinary characters
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'g':
    case 'h':
    case 'i':
    case 'j':
    case 'k':
    case 'l':
    case 'm':
    case 'n':
    case 'o':
    case 'p':
    case 'q':
    case 'r':
    case 't':
    case 'u':
    case 'v':
    case 'w':
    case 'x':
    case 'y':
    case 'z':
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'G':
    case 'H':
    case 'I':
    case 'J':
    case 'K':
    case 'L':
    case 'M':
    case 'N':
    case 'O':
    case 'P':
    case 'Q':
    case 'R':
    case 'S':
    case 'T':
    case 'U':
    case 'V':
    case 'W':
    case 'X':
    case 'Y':
    case 'Z':
    case '_':
    case '.':
      starttoken();
      if (isIdent(lookahead1)) {
	curstate = identifier;
	return start;
      }
      curstate = start;
      return identifier;
    case '0':
      starttoken();
      if (lookahead1 == 'x') {
	curstate = hexstring;
	return start;
      }
      if (isDec(lookahead1)) {
	curstate = decstring;
	return start;
      }
      curstate = start;
      return decstring;
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      starttoken();
      if (isDec(lookahead1)) {
	curstate = decstring;
	return start;
      }
      curstate = start;
      return decstring;
    case '\n':
    case ' ':
    case '\t':
    case '\v':
    case '\r':
      return start;		// Ignore whitespace
    case '\0':
      curstate = endstream;
      return endstream;
    default:
      curstate = illegal;
      return illegal;
    }
    break;
  case special2:
    advancetoken();
    curstate = start;
    return identifier;
  case special3:
    advancetoken();
    curstate = special32;
    return start;
  case special32:
    advancetoken();
    curstate = start;
    return identifier;
  case comment:
    if (curchar == '\n')
      curstate = start;
    else if (curchar == '\0') {
      curstate = endstream;
      return endstream;
    }
    return start;
  case identifier:
    advancetoken();
    if (isIdent(lookahead1))
      return start;
    curstate = start;
    return identifier;
  case hexstring:
    advancetoken();
    if (isHex(lookahead1))
      return start;
    curstate = start;
    return hexstring;
  case decstring:
    advancetoken();
    if (isDec(lookahead1))
      return start;
    curstate = start;
    return decstring;
  default:
    curstate = endstream;
  }
  return endstream;
}

int4 PcodeLexer::getNextToken(void)

{ // Will return either: identifier, punctuation, hexstring, decstring, endstream, or illegal
  // If identifier, hexstring, or decstring,  curtoken will be filled with the characters
  int4 tok;
  do {
    curchar = lookahead1;
    lookahead1 = lookahead2;
    if (endofstream)
      lookahead2 = '\0';
    else {
      s->get(lookahead2);
      if (!(*s)) {
	endofstream = true;
	lookahead2 = '\0';
      }
    }
    tok = moveState();
  } while(tok == start);
  if (tok == identifier) {
    curtoken[tokpos] = '\0';	// Append null terminator
    curidentifier = curtoken;
    int4 num = findIdentifier(curidentifier);
    if (num < 0)			// Not a keyword
      return STRING;
    return idents[num].id;
  }
  else if ((tok == hexstring)||(tok == decstring)) {
    curtoken[tokpos] = '\0';
    istringstream s1(curtoken);
    s1.unsetf(ios::dec | ios::hex | ios::oct);
    s1 >> curnum;
    if (!s1)
      return BADINTEGER;
    return INTEGER;
  }
  else if (tok == endstream) {
    if (!endofstreamsent) {
      endofstreamsent = true;
      return ENDOFSTREAM;	// Send 'official' end of stream token
    }
    return 0;			// 0 means end of file to parser
  }
  else if (tok == illegal)
    return 0;
  return (int4)curchar;
}

void PcodeLexer::initialize(istream *t)

{ // Set up for new lex
  s = t;
  curstate = start;
  tokpos = 0;
  endofstream = false;
  endofstreamsent = false;
  lookahead1 = 0;
  lookahead2 = 0;
  s->get(lookahead1);		// Buffer the first two characters
  if (!(*s)) {
    endofstream = true;
    lookahead1 = 0;
    return;
  }
  s->get(lookahead2);
  if (!(*s)) {
    endofstream = true;
    lookahead2 = 0;
    return;
  }
}

uint4 PcodeSnippet::allocateTemp(void)

{ // Allocate a variable in the unique space and return the offset
  uint4 res = tempbase;
  tempbase += 16;
  return res;
}

void PcodeSnippet::addSymbol(SleighSymbol *sym)

{
  pair<SymbolTree::iterator,bool> res;

  res = tree.insert( sym );
  if (!res.second) {
    reportError((const Location *)0,"Duplicate symbol name: "+sym->getName());
    delete sym;		// Symbol is unattached to anything else
  }
}

void PcodeSnippet::clear(void)

{ // Clear everything, prepare for a new parse against the same language
  SymbolTree::iterator iter,tmpiter;
  iter = tree.begin();
  while(iter != tree.end()) {
    SleighSymbol *sym = *iter;
    tmpiter = iter;
    ++iter;			// Increment now, as node may be deleted
    if (sym->getType() != SleighSymbol::space_symbol) {
      delete sym;		// Free any old local symbols
      tree.erase(tmpiter);
    }
  }
  if (result != (ConstructTpl *)0) {
    delete result;
    result = (ConstructTpl *)0;
  }
  // tempbase = 0;
  errorcount = 0;
  firsterror.clear();
  resetLabelCount();
}

PcodeSnippet::PcodeSnippet(const SleighBase *slgh)
  : PcodeCompile()
{
  sleigh = slgh;
  tempbase = 0;
  errorcount = 0;
  result = (ConstructTpl *)0;
  setDefaultSpace(slgh->getDefaultCodeSpace());
  setConstantSpace(slgh->getConstantSpace());
  setUniqueSpace(slgh->getUniqueSpace());
  int4 num = slgh->numSpaces();
  for(int4 i=0;i<num;++i) {
    AddrSpace *spc = slgh->getSpace(i);
    spacetype type = spc->getType();
    if ((type==IPTR_CONSTANT)||(type==IPTR_PROCESSOR)||(type==IPTR_SPACEBASE)||(type==IPTR_INTERNAL))
      tree.insert(new SpaceSymbol(spc));
  }
  addSymbol(new FlowDestSymbol("inst_dest",slgh->getConstantSpace()));
  addSymbol(new FlowRefSymbol("inst_ref",slgh->getConstantSpace()));
}

PcodeSnippet::~PcodeSnippet(void)

{
  SymbolTree::iterator iter;
  for(iter=tree.begin();iter!=tree.end();++iter)
    delete *iter;		// Free ALL temporary symbols
  if (result != (ConstructTpl *)0) {
    delete result;
    result = (ConstructTpl *)0;
  }
}

void PcodeSnippet::reportError(const Location *loc, const string &msg)

{
  if (errorcount == 0)
    firsterror = msg;
  errorcount += 1;
}

int4 PcodeSnippet::lex(void)

{
  int4 tok = lexer.getNextToken();
  if (tok == STRING) {
    SleighSymbol *sym;
    SleighSymbol tmpsym(lexer.getIdentifier());
    SymbolTree::const_iterator iter = tree.find(&tmpsym);
    if (iter != tree.end())
      sym = *iter;		// Found a local symbol
    else
      sym = sleigh->findSymbol(lexer.getIdentifier());
    if (sym != (SleighSymbol *)0) {
      switch(sym->getType()) {
      case SleighSymbol::space_symbol:
	yylval.spacesym = (SpaceSymbol *)sym;
	return SPACESYM;
      case SleighSymbol::userop_symbol:
	yylval.useropsym = (UserOpSymbol *)sym;
	return USEROPSYM;
      case SleighSymbol::varnode_symbol:
	yylval.varsym = (VarnodeSymbol *)sym;
	return VARSYM;
      case SleighSymbol::operand_symbol:
	yylval.operandsym = (OperandSymbol *)sym;
	return OPERANDSYM;
      case SleighSymbol::start_symbol:
	yylval.startsym = (StartSymbol *)sym;
	return STARTSYM;
      case SleighSymbol::end_symbol:
	yylval.endsym = (EndSymbol *)sym;
	return ENDSYM;
	case SleighSymbol::next2_symbol:
	yylval.next2sym = (Next2Symbol *)sym;
	return NEXT2SYM;
      case SleighSymbol::label_symbol:
	yylval.labelsym = (LabelSymbol *)sym;
	return LABELSYM;
      case SleighSymbol::dummy_symbol:
	break;
      default:
	// The translator may have other symbols in it that we don't want visible in the snippet compiler
	break;
      }
    }
    yylval.str = new string(lexer.getIdentifier());
    return STRING;
  }
  if (tok == INTEGER) {
    yylval.i = new uintb(lexer.getNumber());
    return INTEGER;
  }
  return tok;
}

 bool PcodeSnippet::parseStream(istream &s)

{
  lexer.initialize(&s);
  pcode = this;			// Setup global object for yyparse
  int4 res = yyparse();
  if (res != 0) {
    reportError((const Location *)0,"Syntax error");
    return false;
  }
  if (!PcodeCompile::propagateSize(result)) {
    reportError((const Location *)0,"Could not resolve at least 1 variable size");
    return false;
  }
  return true;
}

void PcodeSnippet::addOperand(const string &name,int4 index)

{ // Add an operand symbol for this snippet
  OperandSymbol *sym = new OperandSymbol(name,index,(Constructor *)0);
  addSymbol(sym);
}

int pcodelex(void) {
  return pcode->lex();
}

int pcodeerror(const char *s)

{
  pcode->reportError((const Location *)0,s);
  return 0;
}

} // End namespace ghidra
