<?php
$includeTraverser = new PHPParser_NodeTraverser;
class IncludeVisitor extends PHPParser_NodeVisitorAbstract
{
    private $modelMode = false;
    public function useModel() {
        $this->modelMode = true;
    }
    private $requestMode = false;
    public function useRequest() {
        $this->requestMode = true;
    }

    private $dynamicIncludeInformation = array();
    private $includeFileStack = array();

    private $systemPath = "";

    /**
     * @var VariableStorage
     */
    private $vScope = null;
    public function setVScope(VariableStorage $scope) {
        $this->vScope = $scope;
    }


    public function beforeTraverse(array $nodes) {
        if ($this->vScope == null) {
            $this->vScope = new VariableStorage();
        }
    }

    /**
     * @param $includeDescription PHPExtBridge_Include[]
     */
    public function addDynamicIncludeResolve($includeDescription) {
        foreach ($includeDescription as $descr) {
            $descr["current"] = realpath($descr["current"]);
            if (!isset($this->dynamicIncludeInformation[$descr["current"]]))
                $this->dynamicIncludeInformation[$descr["current"]] = array();
            if (!isset($this->dynamicIncludeInformation[$descr["current"]][$descr["line"]]))
                $this->dynamicIncludeInformation[$descr["current"]][$descr["line"]] = array();
            $this->dynamicIncludeInformation[$descr["current"]][$descr["line"]][] = $descr["included"];
        }
    }

    public function setSystemPath($path) {
        $this->systemPath = $path;
    }

    public function leaveNode(PHPParser_Node $node) {
        if ($node instanceof PHPParser_Node_Expr_Include) {
            $filename = null;

            if ($this->requestMode) {
                if (isset($this->dynamicIncludeInformation[realpath($node->getFilename())][$node->getLine()])) {
                    $filename = $this->dynamicIncludeInformation[realpath($node->getFilename())][$node->getLine()][0];
                }
            } else {
                if ($node->getLine() != -1) {
                    //print_r($node);
                    //die();
                }

                $taintTraverser = new PHPParser_NodeTraverser();
                $taintVisitor = new BodyVisitor();
                $taintTraverser->addVisitor($taintVisitor);
                $taintVisitor->setVScope($this->vScope);
                $taintVisitor->setVulnerabilityStorage(new VulnerabilityStorage);
                $taintTraverser->traverse(array($node->expr));
                $val = $taintVisitor->getTaint();

                if ($val instanceof VariableValue) {
                    $filename = $val->value;
                }
                if ($filename !== null && substr($filename,0,1) != "/") {
                    $filename = dirname($node->getFilename())."/".$filename;
                }
            }
            $filename = realpath($filename);

            if ($this->modelMode && $node->getLine() != -1) {
                //echo $filename."tried\n";
                if (strpos($filename,$this->systemPath) !== 0) {
                    $filename = null;
                }
            }

            if (is_file($filename)) {
                if (!in_array($filename,$this->includeFileStack)) {
                    global $parser, $includeTraverser;
                    try {
                        $stmts = $parser->parse(new PHPParser_LexerFile($filename));
                        array_push($this->includeFileStack, $filename);
                        $stmts = $includeTraverser->traverse($stmts);
                        //echo array_pop($this->includeFileStack). " was included correctly\n";

                        return $stmts;
                    } catch (PHPParser_Error $e) {
                        echo "Parse error: ".$e->getMessage();
                    }
                } else {
                    //echo $filename." has been included in this part of the tree! - Possible cycle?\n";
                }
            } else {
                //echo $filename." not found\n";
            }

        }
    }
}
$includeVisitor = new IncludeVisitor;
$includeTraverser->addVisitor($includeVisitor);
