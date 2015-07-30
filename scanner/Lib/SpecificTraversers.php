<?php
class FunctionCallResolver extends PHPParser_NodeVisitorAbstract {
    private $funcCallList = array();

    public function getFuncCallList() {
        return $this->funcCallList;
    }

    public function enterNode(PHPParser_Node $node) {
        if ($node instanceof PHPParser_Node_Expr_FuncCall) {
            $funcName = $node->name->parts[0];
            array_push($this->funcCallList,$funcName);
        }
    }
}


class GlobalResolver extends PHPParser_NodeVisitorAbstract {
    /**
     * @var string[] - keeps the names of the variables that are global
     */
    private $globalVars = array();
    public function getGlobalVars() {
        return $this->globalVars;
    }

    public function enterNode(PHPParser_Node $node) {
        if ($node instanceof PHPParser_Node_Stmt_Global) {
            foreach ($node->vars as $var) {
                $this->globalVars[] = $var->name;
            }
        }
    }
}


class NodeCounter extends PHPParser_NodeVisitorAbstract {
    private $c;

    public function beforeTraverse(array $nodes) {
        $this->c = 0;
    }

    public function enterNode(PHPParser_Node $node) {
        $this->c++;
        $node->setNodeNumber($this->c);
    }

    public function afterTraverse(array $nodes) {
        return $this->c;
    }
}

class ModelVisitor extends PHPParser_NodeVisitorAbstract {
    public $functionCallWrapper = array();
    public function setFunctionCallWrappers($wrappers) {
        $this->functionCallWrapper = $wrappers;
    }

    public function leaveNode(PHPParser_Node $node) {
        if ($node instanceof PHPParser_Node_Expr_FuncCall) {
            $funcName = $node->name->parts[0];
            if (array_key_exists($funcName,$this->functionCallWrapper)) {
                global $prettyPrinter;
                $old = printNode($node,true);
                // This only supports single function argugements, should be more.
                $newFuncName = $node->args[end($this->functionCallWrapper[$funcName])]->value->value;
                $node->name->parts[0] = $newFuncName;
                $node->args = array();
                $node->setTHAPSComment("Model rewrite from: ".$old);

            }
        }
    }
}

class ConditionVisitor extends PHPParser_NodeVisitorAbstract {
    private $cleanVars = array();
    private $dirtyVars = array();
    public function getCleanedVars() {
        return $this->cleanVars;
    }
    public function getDirtyVars() {
        return $this->dirtyVars;
    }

    public function beforeTraverse(array $nodes) {
        $this->cleanVars = array();
        $this->dirtyVars = array();
    }

    public function enterNode(PHPParser_Node $node) {
        if ($node instanceof PHPParser_Node_Expr_FuncCall) {
            global $SECURING_IN_IFS;

            $funcName = $node->name->parts[0];
            if (in_array($funcName, $SECURING_IN_IFS)) {
                $arg = $node->args[0];
                $this->cleanVars[] = $arg->value;
            }
        }
        elseif ($node instanceof PHPParser_Node_Expr_BooleanNot) {
            $conditionVisitor = new ConditionVisitor();
            $conditionTranverser = new PHPParser_NodeTraverser();
            $conditionTranverser->addVisitor($conditionVisitor);
            $conditionTranverser->traverse(array($node->expr));

            $this->cleanVars = array_merge($this->cleanVars,$conditionVisitor->getDirtyVars());
            $this->dirtyVars = array_merge($this->dirtyVars,$conditionVisitor->getCleanedVars());
        }
        elseif ($node instanceof PHPParser_Node_Expr_BooleanOr) {
            $conditionVisitor = new ConditionVisitor();
            $conditionTranverser = new PHPParser_NodeTraverser();
            $conditionTranverser->addVisitor($conditionVisitor);
            $conditionTranverser->traverse(array($node->left));
            $leftClean = $conditionVisitor->getCleanedVars();
            $leftDirty = $conditionVisitor->getDirtyVars();

            $conditionTranverser->traverse(array($node->right));
            $rightClean = $conditionVisitor->getCleanedVars();
            $rightDirty = $conditionVisitor->getDirtyVars();


            foreach ($leftClean as $cleanVar) {
                foreach ($rightClean as $cleanVar2) {
                    if ($this->compareVars($cleanVar,$cleanVar2)) {
                        $this->cleanVars = array_merge($this->cleanVars,array($cleanVar));
                    }
                }
            }
            foreach ($leftDirty as $dirtyVar) {
                foreach ($rightDirty as $dirtyVar2) {
                    if ($this->compareVars($dirtyVar,$dirtyVar2)) {
                        $this->dirtyVars = array_merge($this->dirtyVars,array($dirtyVar));
                    }
                }
            }
        }
        elseif ($node instanceof PHPParser_Node_Expr_BooleanAnd) {
            $conditionVisitor = new ConditionVisitor();
            $conditionTranverser = new PHPParser_NodeTraverser();
            $conditionTranverser->addVisitor($conditionVisitor);
            $conditionTranverser->traverse(array($node->left));
            $this->cleanVars = array_merge($this->cleanVars,$conditionVisitor->getCleanedVars());
            $this->dirtyVars = array_merge($this->dirtyVars,$conditionVisitor->getDirtyVars());

            $conditionTranverser->traverse(array($node->right));
            $this->cleanVars = array_merge($this->cleanVars,$conditionVisitor->getCleanedVars());
            $this->dirtyVars = array_merge($this->dirtyVars,$conditionVisitor->getDirtyVars());
        }
        return false;
    }

    private function compareVars($first,$second) {
        if ($first instanceof PHPParser_Node_Expr_ArrayDimFetch &&
            $second instanceof PHPParser_Node_Expr_ArrayDimFetch) {
            return $this->compareVars($first->var,$second->var) && $this->compareVars($first->dim,$second->dim);
        }
        elseif ($first instanceof PHPParser_Node_Expr_ConstFetch &&
                $second instanceof PHPParser_Node_Expr_ConstFetch &&
                $first->name->parts[0] == $second->name->parts[0]) {
            return true;
        }
        elseif ($first instanceof PHPParser_Node_Expr_Variable &&
                $second instanceof PHPParser_Node_Expr_Variable &&
                $first->name == $second->name) {
            return true;
        }
        elseif ($first instanceof PHPParser_Node_Scalar &&
                $second instanceof PHPParser_Node_Scalar &&
                $first->value == $second->value) {
            return true;
        }
        return false;
    }
}