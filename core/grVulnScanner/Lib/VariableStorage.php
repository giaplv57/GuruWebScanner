<?php
class VariableValue {
    /**
     * @var bool
     */
    public $userInput;
    /**
     * @var bool
     */
    public $xss;
    /**
     * @var bool
     */
    public $sql;

    /**
     * @var array
     */
    public $dependencies = array();
    /**
     * @var array
     */
    public $flowpath = array();

    /**
     * @var string
     */
    public $value = "";

    public function VariableValue($defaultTaint = false) {
        $this->userInput = $defaultTaint;
        $this->xss = $defaultTaint;
        $this->sql = $defaultTaint;
        if ($defaultTaint == true) {
            $this->value = "{USERINPUT_XSS_SQL}";
        }
    }

    function __clone() {
        foreach($this as $key => $val) {
            if(is_object($val)||(is_array($val))){
                $this->{$key} = unserialize(serialize($val));
            }
        }
    }

    function __toString() {
        return "value:".$this->value.($this->userInput?" has UI":"").($this->xss?" has XSS":"").($this->sql?" has SQL":"");
    }


}

class VariableStorage {
    /**
     * The name of the direct dependency
     * @var string
     */
    public $dependency = "";
    /**
     * @var VariableStorage[]
     */
    private $scopeDictionary = array();
    /**
     * The assignments which is dependent directly on this
     * @var VariableValue[]
     */
    public $variables = array();

    /**
     * The parent scope
     * @var VariableStorage
     */
    public $parentScope = null;
    /**
     * The sub scopes
     * @var VariableStorage[]
     */
    public $subScopes = array();
    /**
     * If the current scope is no longer a endpoint scope
     * @var bool
     */
    private $closed = false;


    private $watches = array();
    public function addWatch($var) {
        if (!in_array($var,$this->watches))
            $this->watches[] = $var;
    }
    public function removeWatch($var) {
        if ($key = array_search($var,$this->watches) !== false)
            unset($this->watches[$key]);
    }

    static private $ignoreFlow = false;
    static public function ignoreFlow() {
        self::$ignoreFlow = true;
    }


    public function &getSubstorage($dependency) {
        $result = null;
        foreach ($this->subScopes as $subScope) {
            if ($subScope->dependency == $dependency) {
                $result = &$subScope;
                return $result;
            }
        }
        return $result;
    }
    public function &addSubstorage($dependency,$closed = false) {
        $tmpStorage = new VariableStorage();
        $tmpStorage->scopeDictionary = &$this->scopeDictionary;
        $tmpStorage->dependency = $dependency;
        $tmpStorage->parentScope = &$this;
        $this->subScopes[] = &$tmpStorage;
        $this->closed = $closed;
        if (!isset($this->scopeDictionary[$dependency])) {
            $this->scopeDictionary[$dependency] = array();
        }
        $this->scopeDictionary[$dependency][] = $tmpStorage;
        $tmpStorage->watches = &$this->watches;
        return $tmpStorage;
    }

    public function getVariableValue($varName) {
        $numArgs = func_num_args();
        $watch = in_array($varName,$this->watches);

        if ($watch) {
            $watchString = "$".$varName;
            for ($a = 1; $a < $numArgs; $a++) {
                $arg = func_get_arg($a);
                if ($arg === null || is_object($arg) || is_array($arg)) {
                    break;
                }
                $watchString.="['".$arg."']";
            }
        }

        $scope = $this;
        $elm = null;


        do {
            $target = $scope->variables;
            for ($a = 0; $a < $numArgs; $a++) {
                $arg = func_get_arg($a);
                if ($arg === null || is_object($arg) || is_array($arg)) {
                    $elm = null;
                    break 2;
                }

                if ((is_array($target) || $target instanceof ArrayAccess) && isset($target[$arg])) {

                    if ($a == $numArgs - 1) {
                        $elm = $target[$arg];
                    } else {
                        $target = $target[$arg];

                    }
                } else {
                    break;
                }
            }
            if($elm === null) {
                $scope = $scope->parentScope;
            }
        } while ($elm === null && $scope !== null);


        if ($elm instanceof ClassPropertyDescription) {
            $elm = $elm->value;
        }

        if ($elm == null) {
            if ($watch) {
                echo $watchString." is null\n";
            }
            return null;
        } else if ($elm instanceof VariableValue || $elm instanceof ClassDescription) {
            if ($watch) {
                if ($elm instanceof ClassDescription) {
                    echo $watchString.' is '.$elm->name." \n";
                } else {
                    echo $watchString.' is '.$elm." \n";
                }
            }
            return clone $elm;
        } else if (is_array($elm)) {
            // It has to be an array, time to get parent values
            $array = array();

            do {
                $target = $scope->variables;
                for ($a = 0; $a < $numArgs; $a++) {
                    $arg = func_get_arg($a);
                    if ((is_array($target) || $target instanceof ArrayAccess) && isset($target[$arg]) && is_array($target[$arg])) {
                        if ($a == $numArgs - 1) {
                            $array = array_merge($target[$arg],$array);
                        } else {
                            $target = $target[$arg];
                        }
                    } else {
                        break;
                    }
                }
                $scope = $scope->parentScope;
            } while ($scope !== null);

            if ($watch) {
                echo $watchString." is ".print_r($array,true);
            }

            return $array;
        } else {
            // WTF IS IT??
            var_dump($elm);
            die("I DONT KNOW THIS\n");
        }
    }

    function __clone() {
        foreach($this as $key => $val) {
            if(is_object($val)||(is_array($val))){
                $this->{$key} = unserialize(serialize($val));
            }
        }
    }


    /**
     * Get the possible variable scopes given a dependency tree
     * @param array $dependencies
     * @return VariableStorage[]
     */
    public function getVariableValueConfigurations(array $dependencies = array()) {
        $candidates = array();
        if (end($dependencies) != "") {
            $candidates = $this->scopeDictionary[end($dependencies)];
        }
        $candidates[] = $this;

        $result = array();
        foreach ($candidates as $candidate) {
            $found = true;
            $target = $candidate;
            foreach (array_reverse($dependencies) as $dependency) {
                while ($target->parentScope != null && $target->dependency != $dependency) {
                    $target = $target->parentScope;
                }
                if ($dependency != $target->dependency) {
                    $found = false;
                    break;
                }
                $target = $target->parentScope;
            }
            if ($found) {
                $result = array_merge($result,$this->traverseScope($candidate));
            }
        }

        return $result;
    }

    /**
     * Returns the scopes below a given dependency as they are also possible scopes
     * @param VariableStorage $scope
     * @return array
     */
    private function traverseScope(VariableStorage $scope) {
        $scopes = array();
        if (!$scope->closed) {
            // There is no else on the dependency, lets add the values as they are good!
            $scopes[] = &$scope;
        }
        foreach ($scope->subScopes as $subDependency) {
            $scopes = array_merge($scopes, $this->traverseScope($subDependency));
        }
        return $scopes;
    }
    /**
     * Sets a variable value in the given dependency scope. If dependency scope does not exists, add them to all posibilities
     * @param array $dependencies
     * @param $varName
     * @param $value
     */
    public function setVariableValue($value,$varName) {
        $numArgs = func_num_args();
        $watchString = "";

        $watch = in_array($varName,$this->watches);
        if ($watch) {
            $watchString = "$".$varName;
        }


        if ($numArgs === 2) {
            $this->variables[$varName] = $value;
        } else {

            if (!isset($this->variables[$varName])) {
                $this->variables[$varName] = array();
            }
            $target = &$this->variables[$varName];

            for ($a = 2; $a < $numArgs; $a++) {
                $arg = func_get_arg($a);
                if ($target instanceof VariableValue) {
                    $target = array();
                }
                if ($arg === VAR_REP_NEW) {
                    $target[] = array();
                    $arg = end(array_keys($target));

                } else if (!isset($target[$arg])) {
                    $target[$arg] = array();
                }
                if ($watch) {
                    $watchString .= "[".$arg."]";
                }


                if ($target instanceof ClassDescription) {
                    $target = &$target->getProperty($arg)->value;
                } else {
                    $target = &$target[$arg];
                }


            }

            if ($target instanceof ClassPropertyDescription) {
                $target->value = $value;
            } else {
                $target = $value;
            }
        }

        if ($watch) {
            if ($value instanceof ClassDescription)
                $value = $value->name;
            echo $watchString." = ".$value."\n";
        }
    }

    public function cleanUp() {
        $same = true;
        $candidates = $this->getVariableValueConfigurations(array());
        if (($key = array_search($this,$candidates)) !== false) {
            unset($candidates[$key]);
        }
        $candOne = array_pop($candidates);
        $candOneSerialized = serialize($candOne);
        while (($candTwo = array_pop($candidates)) !== null) {
            if (count($candTwo->variables) == count($candOne->variables)) {
                foreach ($candOne->variables as $key => $val) {
                    $valTwo = isset($candTwo->variables[$key])?$candTwo->variables[$key]:null;
                    if ($val instanceof VariableValue) {
                        if ($valTwo == null ||
                            !($valTwo instanceof VariableValue) ||
                            $val->xss != $valTwo->xss ||
                            $val->sql != $valTwo->sql ||
                            $val->userInput != $valTwo->userInput ||
                            (!self::$ignoreFlow && $candOneSerialized != serialize($candTwo))) {
                            $same = false;
                            break 2;
                        }
                    } else {
                        // Val must be an array - count is not enough, but fine for now.
                        if ($valTwo instanceof VariableValue ||
                            count($valTwo) != count($val)) {
                            $same = false;
                            break 2;
                        }
                    }
                }
            } else {
                $same = false;
                break;
            }
        }

        if ($same) {
            $this->closed = false;
            $this->variables = array_merge($this->variables,$candOne->variables);

            foreach ($this->subScopes as $subScope) {
                $key = array_search($subScope,$this->scopeDictionary[$subScope->dependency]);
                unset($this->scopeDictionary[$subScope->dependency][$key]);
            }

            $this->subScopes = array();
        }
    }
}

function printVariableValue($varName, $item, $spacer = 0) {
    if (is_array($item) || $item instanceof Traversable) {
        foreach ($item as $v) {
            //var_dump($v);
            printVariableValue($varName, $v, $spacer+1);
        }
    } else {
        echo $varName . "[" . $item->name . "]=";
        if ($item instanceof ClassPropertyDescription) {
            $item = $item->value;
        }
        echo ($item->xss ? "true" : "false") . ",";
        echo ($item->sql ? "true" : "false") . "\n";
    }
}

function printVariableStorage(VariableStorage $item) {

    foreach ($item->variables as $varName => $var) {
        printVariableValue($varName, $var);
    }

}

function printVariableStorageStructure(VariableStorage $item,$spacer = 0) {
    echo str_repeat(" ", $spacer * 4);
    echo $item->dependency."\n";
    foreach ($item->subScopes as $sub) {
        printVariableStorageStructure($sub,$spacer+1);
    }
}