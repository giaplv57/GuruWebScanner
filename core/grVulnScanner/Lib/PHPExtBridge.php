<?php
class PHPExt {

    /** @var Mongo */
    private static $db;

    /** @var MongoCollection */
    private static $coll;

    /** @var MongoCursor */
    private static $data;

    private static function connect() {
        if (self::$db === null) {
            $conf = parse_ini_file(THAPS_DIR ."configuration.ini");
            self::$db = @new Mongo('mongodb://'. $conf['db.user'] .":". $conf['db.pass'] .'@'. $conf['db.host'] .':'. $conf['db.port'] .'/local');
            self::$coll = self::$db->local->thaps;
        }
    }

    public static function disconnect() {
        if (self::$db !== null) {
            self::$db->close();
            self::$db = null;
        }
    }

    public static function setRequestId($id) {
        self::setCustomField("_id", new MongoId($id));
    }

    public static function setCustomField($field, $value) {
        self::connect();
        self::$data = @self::$coll->findOne(array($field => $value));
    }

    public static function exists() {
        $id = self::getId();
        return !empty($id);
    }

    public static function getId() {
        return "".self::$data["_id"];
    }

    public static function getRequest() {
        return "".self::$data["request"];
    }

    public static function getFilename() {
        return "".self::$data["filename"];
    }

    public static function getIncludes() {
        return self::$data["includes"];
    }

    public static function getFunctions() {
        return self::$data["functions"];
    }

    public static function getVariables() {
        return self::$data["variables"];
    }

    public static function setVulnerabilities($vulnerabilities) {
        self::$data["vulnerabilities"] = $vulnerabilities;
        self::$coll->save(self::$data, array("safe" => true));
    }

}
