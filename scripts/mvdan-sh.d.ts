// Minimal ambient types for mvdan-sh (ships no .d.ts): the parser surface scripts/check-moon-edges.ts reads.
// The nodes are Go's mvdan.cc/sh/v3/syntax structs under their Go field names; a node's type is only known
// through syntax.NodeType, so a reader narrows by that string and casts.
declare module "mvdan-sh" {
  export interface Node {
    Pos: () => { Line: () => number; Col: () => number; Offset: () => number };
  }
  /** Text as written: a backslash and a glob character keep their source form, and the enclosing quotes say what they mean. */
  export interface Lit extends Node {
    Value: string;
  }
  export interface SglQuoted extends Node {
    Value: string;
  }
  export interface DblQuoted extends Node {
    Parts: Node[];
  }
  export interface ParamExp extends Node {
    Param: Lit;
  }
  export interface ExtGlob extends Node {
    Pattern: Lit;
  }
  export interface Word extends Node {
    Parts: Node[];
  }
  /** `NAME=value`; Name is null for a bare word in a declaration such as `local -r`. */
  export interface Assign extends Node {
    Name: Lit | null;
    Value: Word | null;
  }
  /** A simple command; the assignments before its name are Assigns, not Args. */
  export interface CallExpr extends Node {
    Assigns: Assign[];
    Args: Word[];
  }
  /** `export`, `declare`, `local`, `readonly`, `typeset`, or `nameref` with its assignments. */
  export interface DeclClause extends Node {
    Variant: Lit;
    Args: Assign[];
  }
  /** Op is syntax.RedirOperator's number; Hdoc is a heredoc's body, null for every other operator and for an empty body. */
  export interface Redirect extends Node {
    Op: number;
    Word: Word;
    Hdoc: Word | null;
  }
  export interface WhileClause extends Node {
    Until: boolean;
  }
  /** Negated is a leading `!`, which inverts the command's exit status. */
  export interface Stmt extends Node {
    Cmd: Node | null;
    Negated: boolean;
    Redirs: Redirect[];
  }
  export interface File extends Node {
    Name: string;
  }
  export interface Parser {
    Parse: (src: string, name: string) => File;
  }
  /** What Parser.Parse throws: a Go error object, not a JS Error. */
  export interface ParseError {
    Filename: string;
    Text: string;
    Incomplete: boolean;
    Error: () => string;
  }
  const sh: {
    syntax: {
      NewParser: () => Parser;
      NodeType: (node: Node) => string;
      /** Visits root and every node under it; visit returns whether to descend, and is called with null after each subtree. */
      Walk: (root: Node, visit: (node: Node | null) => boolean) => void;
    };
  };
  export default sh;
}
