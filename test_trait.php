<?php

trait MyTrait {
    private function myPrivateMethod() {
        return "Hello from private trait method!";
    }

    public function myPublicMethod() {
        return $this->myPrivateMethod();
    }
}

class MyClass {
    use MyTrait;
}

$obj = new MyClass();
echo $obj->myPublicMethod() . "\n";
