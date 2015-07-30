<?php
$classTraverser = new PHPParser_NodeTraverser;

function classGetVisibility($type) {
    switch ($type) {
        case ($type & 1) == 1: return CLASS_VISIBILITY_PUBLIC;
        case ($type & 2) == 2: return CLASS_VISIBILITY_PROTECTED;
        case ($type & 4) == 4: default: return CLASS_VISIBILITY_PRIVATE;
    }
}

abstract class Cloneable {
    function __clone() {
        foreach(get_object_vars($this) as $key => $val) {
            if(is_object($val)||(is_array($val))){
                $this->{$key} = unserialize(serialize($val));
            }
        }
    }
}

class ClassStorage {

    /** @var ClassDescription[] */
    private static $classes;

    public static function addClass(ClassDescription $class) {
        self::$classes[$class->name] = $class;
    }

    /**
     * @static
     * @param $class string
     * @return ClassDescription
     */
    public static function getClass($class) {
        return isset(self::$classes[$class]) ? clone self::$classes[$class] : null;
    }

    /***
     * @static
     * @return ClassDescription[]
     */
    public static function getClasses() {
        return self::$classes;
    }

}

class ClassPropertyDescription extends Cloneable implements ArrayAccess {

    /** @var string */
    public $name;

    /** @var string */
    public $visibility;

    public $value;

    public function offsetExists($offset) {
        return is_array($this->value) && isset($this->value[$offset]);
    }

    public function offsetGet($offset) {
        return is_array($this->value) && isset($this->value[$offset]) ? $this->value[$offset] : null;
    }

    public function offsetSet($offset, $value) {
        if (!is_array($this->value) && $this->value == null) {
            $this->value = array();
        }
        if (is_array($this->value)) {
            $this->value[$offset] = $value;
        }
    }

    public function offsetUnset($offset) {
        unset($this->value[$offset]);
    }
}


class ClassMethodDescription extends Cloneable {

    /** @var string */
    public $name;

    /** @var string */
    public $visibility;

    /** @var boolean */
    public $parsed = false;

    /** @var PHPParser_Node */
    public $node;

    /** @var array */
    public $dependencies = array();

    public $alwaysVulnerable = array();

    public $returnAlwaysVulnerable = array();

    public $vulnerableParameters = array();

    public $returnVulnerableParameters = array();

    public $vulnerableProperties = array();

    public $returnVulnerableProperties = array();

    public $propertyVulnerable = array();

    public $propertyVulnerableParameters = array();

    public $propertyVulnerableProperty = array();


}

class ClassDescription extends Cloneable implements ArrayAccess, Iterator, Countable {

    /** @var string */
    public $extends = null;

    /** @var ClassConstantDescription[] */
    public $constants = array();

    /** @var ClassPropertyDescription[] */
    public $properties = array();

    /** @var ClassMethodDescription[] */
    public $methods = array();

    /** @var string */
    public $name;

    public function __construct($name) {
        $this->name = $name;
    }

    public function addProperty($property) {
		$this->properties[$property->name] = $property;
    }

    public function extendProperties($properties) {
		foreach ($properties as $property) {
			if ($property->visibility == CLASS_VISIBILITY_PUBLIC || $property->visibility == CLASS_VISIBILITY_PROTECTED)
				$this->addProperty($property);
		}
    }

    public function addConstant(ClassConstantDescription $constant) {
        $this->constants[$constant->name] = $constant;
    }

    public function addMethod($method) {
		$this->methods[$method->name] = $method;
    }

    public function extendMethods($methods) {
		foreach ($methods as $method) {
			if ($method->visibility == CLASS_VISIBILITY_PUBLIC || $method->visibility == CLASS_VISIBILITY_PROTECTED)
				$this->addMethod($method);
		}
    }
    public function getMethod($method) {
        return isset($this->methods[$method]) ? $this->methods[$method] : null;
    }
    public function getMethods() {
        return $this->methods;
    }

    public function getProperty($property) {
        return isset($this->properties[$property]) ? $this->properties[$property] : null;
    }

    public function getProperties() {
        return $this->properties;
    }


    /* ArrayAccess implementation */
    public function offsetExists($offset) {
        return isset($this->properties[$offset]);
    }

    public function offsetGet($offset) {
        return isset($this->properties[$offset]) ? $this->properties[$offset] : null;
    }

    public function offsetSet($offset, $value) {
        if (isset($this->properties[$offset]))
            $this->properties[$offset] = $value;
    }

    public function offsetUnset($offset) {
        unset($this->properties[$offset]);
    }

    /* Iterator implementation */
    public function current() {
        return current($this->properties);
    }

    public function next() {
        return next($this->properties);
    }

    public function key() {
        return key($this->properties);
    }

    public function valid() {
        return $this->current() !== false;
    }

    public function rewind() {
        reset($this->properties);
    }

    /* Countable implementation */
    public function count() {
        return count($this->properties);
    }
}

class ClassConstantDescription {
    public $name;
    public $value;
}

class ClassVisitor extends PHPParser_NodeVisitorAbstract {

    private $worklist = array();
    /** @var ClassDescription[] */
    private $foundClasses = array();
    private $currentClass;
    private $currentMethod;

    private $vScope = null;

    private $assignNewCombo = array();

    public function setVScope($scope) {
        $this->vScope = $scope;
    }

    public function beforeTraverse(array $nodes) {
        if ($this->vScope == null) {
            $this->vScope = new VariableStorage;
        }
    }

    public function leaveNode(PHPParser_Node $node) {
        if ($node instanceof PHPParser_Node_Stmt_Class) {

            $class = new ClassDescription($node->name);
            if ($node->extends != null)
                $class->extends = $node->extends->parts[0];

            foreach ($node->stmts as $classStatements) {

                if ($classStatements instanceof PHPParser_Node_Stmt_Property) {
                    $property = new ClassPropertyDescription();
                    $property->name = $classStatements->props[0]->name;
                    $property->visibility = classGetVisibility($classStatements->type);
                    $class->addProperty($property);
                } else if ($classStatements instanceof PHPParser_Node_Stmt_ClassMethod) {
                    $method = new ClassMethodDescription();
                    $method->name = $classStatements->name;
                    $method->node = $classStatements;
                    $method->visibility = classGetVisibility($classStatements->type);
                    $class->addMethod($method);
                    $this->currentMethod = $method->name;
                } else if ($classStatements instanceof PHPParser_Node_Stmt_ClassConst) {
                    foreach ($classStatements->consts as $const) {
                        $classConst = new ClassConstantDescription();
                        $classConst->name = $const->name;
                        // This might need to use body resolvers!?
                        $classConst->value = $const->value->value;

                        $class->addConstant($classConst);
                    }
                }
            }
            $this->foundClasses[$node->name] = $class;
            $this->currentClass = $class->name;
            return false;
        }
        elseif ($node instanceof PHPParser_Node_Expr_Assign) {
            if ($node->expr instanceof PHPParser_Node_Expr_New) {
                $parser = new PHPParser_Parser;
                $prettyPrinter = new PHPParser_PrettyPrinter_Zend;
                $constructorCall = $parser->parse(new PHPParser_Lexer("<?php ".substr($prettyPrinter->prettyPrint(array($node->var)),0,-1)."->__construct();"));
                $constructorCall[0]->args = $node->expr->args;
                return array_merge(array($node),$constructorCall);
            }
        }
    }

    public function afterTraverse(array $nodes) {

        // Add properties and methods to extending classes
        foreach ($this->foundClasses as $className => $class) {
            ClassStorage::addClass($class);
            $baseClass = $class;
            while ($baseClass != null && $baseClass->extends != null) {
                if (!class_exists($baseClass->extends)) {
                    // TODO: Ignore builtin classes atm, they should be implemented later
                    if (isset($this->foundClasses[$baseClass->extends])) {
                        ClassStorage::getClass($className)->extendProperties($this->foundClasses[$baseClass->extends]->properties);
                        ClassStorage::getClass($className)->extendMethods($this->foundClasses[$baseClass->extends]->methods);
                        $baseClass = $this->foundClasses[$baseClass->extends];
                    } else {
                        $baseClass = null;
                    }
                } else {
                    $baseClass = null;
                }

            }
            foreach ($class->methods as $method) {
                $this->parseMethod($className, $method);
            }
        }
    }

    private function parseMethod($className, ClassMethodDescription $method) {

        if ($method->parsed)
            return;

        // prevent cyclic method calls
        //$this->worklist[] = $className ."::". $method->name;

        $params = array();
        $props = array();
        $vars = clone $this->vScope;

        $class = ClassStorage::getClass($className);
        $vars->setVariableValue($class, "this");

        global $parsedClass;
        $parsedClass = $className;

        $properties = $class->getProperties();
        foreach ($properties as $propNr => $property) {
            $vars->setVariableValue(new VariableValue(true), "this", $property->name);
            $props[$propNr] = "this->" . $property->name;
        }

        foreach ($method->node->params as $paramNr => $param) {
            $vars->setVariableValue(new VariableValue(true), $param->name);
            $params[$paramNr] = $param->name;
        }

        $bodyVisitor = new BodyVisitor;
        $bodyTraverser = new PHPParser_NodeTraverser;
        $bodyTraverser->addVisitor($bodyVisitor);
        $bodyVisitor->setVScope($vars);
        $bodyVisitor->setVulnerabilityStorage(new VulnerabilityStorage);
        $methodVulnerabilities = $bodyTraverser->traverse($method->node->stmts);

        if (count($methodVulnerabilities) > 0) {

            foreach ($methodVulnerabilities as $nr => $vuln) {
                $vulnParamName = vulnOriginsFromVar($vuln->flowpath);

                if (in_array($vulnParamName,$params)) {
                    if ($vuln->return) {
                        if (!isset($method->returnVulnerableParameters[array_search($vulnParamName,$params)]))
                            $method->returnVulnerableParameters[array_search($vulnParamName,$params)] = array();
                        $method->returnVulnerableParameters[array_search($vulnParamName,$params)][] = $vuln;
                    } else {
                        if (!isset($method->vulnerableParameters[array_search($vulnParamName,$params)]))
                            $method->vulnerableParameters[array_search($vulnParamName,$params)] = array();
                        $method->vulnerableParameters[array_search($vulnParamName,$params)][] = $vuln;
                    }
                } else if (in_array($vulnParamName,$props)) {
                    $vulnParamName = substr($vulnParamName, 6);
                        if ($vuln->return) {
                            if (!isset($method->returnVulnerableProperties[$vulnParamName]))
                                $method->returnVulnerableProperties[$vulnParamName] = array();
                            $method->returnVulnerableProperties[$vulnParamName][] = $vuln;
                        } else {
                            if (!isset($method->vulnerableProperties[$vulnParamName]))
                                $method->vulnerableProperties[$vulnParamName] = array();
                            $method->vulnerableProperties[$vulnParamName][] = $vuln;
                        }
                } else {
                    if ($vuln->return) {
                        $method->returnAlwaysVulnerable[] = $vuln;
                    } else {
                        $method->alwaysVulnerable[] = $vuln;
                    }
                }
            }
        }
        $variableConfigurations = $vars->getVariableValueConfigurations(array());

        foreach ($properties as $propNr => $property) {
            foreach ($variableConfigurations as $variableConfiguration) {
                $taintInfo = $variableConfiguration->getVariableValue("this",$property->name);
                if ($taintInfo !== null && $taintInfo instanceof VariableValue) {
                    $vulnParamName = vulnOriginsFromVar($taintInfo->flowpath);
                    if (($key = array_search($vulnParamName,$params)) !== false) {
                        if (!isset($method->propertyVulnerableParameters[$property->name])) {
                            $method->propertyVulnerableParameters[$property->name] = array();
                        }
                        $method->propertyVulnerableParameters[$property->name][$key] = $taintInfo;
                    } else {
                        $method->propertyVulnerable[$property->name] = $taintInfo;
                    }//else if ()
                }
            }
        }

        $method->parsed = true;
    }

}


$classVisitor = new ClassVisitor();
$classTraverser->addVisitor($classVisitor);
