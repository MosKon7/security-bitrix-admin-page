<?php
use Bitrix\Main;
use Bitrix\Main\Loader;


/* Определение на административной странице */
$request = \Bitrix\Main\Context::getCurrent()->getRequest();
if($request->isAdminSection()) {
    \Bitrix\Main\Loader::includeModule('security');

    $UserIP = get_ip();
    /* Получаем список исключений */
    $rsIPRule = CSecurityIPRule::GetList(array(), array(
        "=RULE_TYPE" => "A",
        "=ADMIN_SECTION" => "Y",
        "=SITE_ID" => false,
        "=SORT" => 10,
        "=ACTIVE_FROM" => false,
        "=ACTIVE_TO" => false,
    ), array("ID" => "ASC"));

    $arIPRule = $rsIPRule->Fetch();
    if($arIPRule) {
        $ID = $arIPRule["ID"];
        $ACTIVE = $arIPRule["ACTIVE"];
    }else {
        $ID = 0;
        $ACTIVE = "N";
    }

    $ar = CSecurityIPRule::GetRuleExclIPs($ID);
    foreach($ar as $i => $ip) {
        $arExclIPs[] = htmlspecialcharsbx($ip);
    }

    /* Если нету в белом списке */
    if(isset($arExclIPs) && !in_array($UserIP,$arExclIPs)){
        /* Создаем правило и добавляем в Стоп-Лист*/
        $rule = new CSecurityIPRule();
        $arFields = array(
            "RULE_TYPE" => "M",
            "ACTIVE" => "Y",
            "ADMIN_SECTION" => "Y",
            "SITE_ID" => false,
            "SORT" => "500",
            "NAME" => "Забанен за попытку перехода в административный раздел: '".$UserIP."'",
            "ACTIVE_FROM" => date("d.m.Y H:i:s"),
            "ACTIVE_TO" => "",
            "INCL_IPS" => array("n0"=>$UserIP),
            "EXCL_IPS" => array("n0"=>""),
            "INCL_MASKS" => array("n0"=>"/*"),
            "EXCL_MASKS" => array("n0"=>""),
        );
        $result = $rule->Add($arFields);

        /*Редирект на 404 на всякий случай*/
        global $APPLICATION;
        $APPLICATION->RestartBuffer();
        CHTTP::SetStatus("404 Not Found");
        LocalRedirect("/404.php", "404 Not Found");
    }
}

function get_ip()
{
    $value = '';
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $value = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $value = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $value = $_SERVER['REMOTE_ADDR'];
    }

    return $value;
}
