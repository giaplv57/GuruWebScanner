<?php

abstract class PHPParser_NodeAbstract implements PHPParser_Node, IteratorAggregate
{
    protected $nodeNumber;
    protected $subNodes;
    protected $line;
    protected $filename;
    protected $docComment;
    protected $thapsComment;

    /**
     * Creates a Node.
     *
     * @param array       $subNodes   Array of sub nodes
     * @param int         $line       Line
     * @param null|string $docComment Nearest doc comment
     */
    public function __construct(array $subNodes, $line = -1, $filename, $docComment = null, $nodeNumber = -1,$thapsComment = null) {
        $this->subNodes     = $subNodes;
        $this->line         = $line;
        $this->filename     = $filename;
        $this->docComment   = $docComment;
        $this->nodeNumber   = $nodeNumber;
        $this->thapsComment = $thapsComment;
    }

    /**
     * Gets the type of the node.
     *
     * @return string Type of the node
     */
    public function getType() {
        return substr(get_class($this), 15);
    }

    /**
     * Gets the names of the sub nodes.
     *
     * @return array Names of sub nodes
     */
    public function getSubNodeNames() {
        return array_keys($this->subNodes);
    }

    /**
     * Gets line the node started in.
     *
     * @return int Line
     */
    public function getLine() {
        return $this->line;
    }

    /**
     * Gets filename the node started in.
     *
     * @return string Filename
     */
    public function getFilename() {
        return $this->filename;
    }

    /**
     * Sets line the node started in.
     *
     * @param int $line Line
     */
    public function setLine($line) {
        $this->line = (int) $line;
    }

    /**
     * Gets the nearest doc comment.
     *
     * @return null|string Nearest doc comment or null
     */
    public function getDocComment() {
        return $this->docComment;
    }

    /**
     * Sets the nearest doc comment.
     *
     * @param null|string $docComment Nearest doc comment or null
     */
    public function setDocComment($docComment) {
        $this->docComment = $docComment;
    }

    /**
     * Gets the THAPS comment.
     *
     * @return null|string THAPS comment or null
     */
    public function getTHAPSComment() {
        return $this->thapsComment;
    }

    /**
     * Sets the THAPS comment.
     *
     * @param null|string $comment THAPS comment or null
     */
    public function setTHAPSComment($comment) {
        $this->thapsComment = $comment;
    }

    public function getNodeNumber() {
        return $this->nodeNumber;
    }

    public function setNodeNumber($number) {
        $this->nodeNumber = $number;
    }

    /* Magic interfaces */

    public function &__get($name) {
        return $this->subNodes[$name];
    }
    public function __set($name, $value) {
        $this->subNodes[$name] = $value;
    }
    public function __isset($name) {
        return isset($this->subNodes[$name]);
    }
    public function __unset($name) {
        unset($this->subNodes[$name]);
    }
    public function getIterator() {
        return new ArrayIterator($this->subNodes);
    }
}