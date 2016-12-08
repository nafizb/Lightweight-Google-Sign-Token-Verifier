<?php
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Key; // just to make our life simpler
use Lcobucci\JWT\Signer\Rsa\Sha256;

class GoogleTokenVerifier {

    private $certRepo = 'https://www.googleapis.com/oauth2/v1/certs';
    private $certFile = APP_PATH . 'app/config/google_cert.json';
    private $certCacheTime = 3600; // 3600 seconds = 1 hour
    private $certData;

    private $signer;
    private $validationData;

    private $token;

    private $issuer = 'https://accounts.google.com';
    private $audience = '<Your audience key>';

    public function __construct($rawToken)
    {
        $this->signer = new Sha256();
        $this->validationData = new ValidationData();

        $this->token = (new Parser())->parse((string) $rawToken);

        $this->loadCerts();
        $this->setValidators();
    }

    private function loadCerts() {
        //Check cert file and update cached certs if time expired.
        if(!file_exists($this->certFile) || filemtime($this->certFile) + $this->certCacheTime < time()) {
            $certJson = file_get_contents($this->certRepo);
            file_put_contents($this->certFile, $certJson);
        } else {
            $certJson = file_get_contents($this->certFile);
        }
        $this->certData = json_decode($certJson);
    }

    private function setValidators() {
        $this->validationData->setIssuer($this->issuer);
        $this->validationData->setAudience($this->audience);
    }

    private function getKid() {
        return $this->token->getHeader('kid');
    }
    public function getClaim() {
        return $this->token->getClaims();
    }

    public function validate() {
        return $this->token->validate($this->validationData);
    }

    public function verifySign() {
        $publicKey = $this->certData->{$this->getKid()};
        return $this->token->verify($this->signer, new Key($publicKey));
    }

    public function verifyToken() {
        return $this->validate() && $this->verifySign();
    }
}