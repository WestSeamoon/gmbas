use elliptic_curve::rand_core::{OsRng};
use hex_literal::hex;
use mysql::prelude::*;
use mysql::*;
//use k256::sm2::SigningKey;

//#[derive(Debug)];

//#[derive(Debug)];

fn main() {
    
        //困难关系对生成
        let sum_diff = k256::sm2::SigningKey::gen_diff(&mut OsRng);
        let y_key = hex::encode_upper(sum_diff.0);
        let y_upper_key = hex::encode_upper(sum_diff.1);
        println!("生成y的值为{:#?}\n",y_key);
        println!("生成Y的值为{:#?}\n",y_upper_key);
       
    
        //密钥对生成
        let sum_key = k256::sm2::SigningKey::gen_key(&mut OsRng);
        let secret_key = hex::encode_upper(sum_key.0);
        let pub_key = hex::encode_upper(sum_key.1);
        println!("生成的私钥值为{:#?}\n",secret_key);
        println!("生成的公钥值为{:#?}\n",pub_key);

/* 
        //把公钥放mysql
        //连接数据库，设置连接字符串
        let url = "mysql://root:122513gzhGZH!!@decs.pcl.ac.cn:1762/search_engine";
        //let opts = Opts::from_url(url).unwrap();// 类型转换将 url 转为opts
         //连接数据库 老版本直接传url字符串,新版本21版要求必须为opts类型
        let pool = Pool::new(url).unwrap();
        let mut conn = pool.get_conn().unwrap();
    
        //数据库操作
        let stmt = conn.prep("insert into regist(id, public_key) values (?, ?)").unwrap();
        let ret = conn.exec_iter(stmt, (123, pub_key)).unwrap();
        println!("{:?}", ret.affected_rows());
        //let stmt = conn.prep("insert into regist (id, public_key) values (:id, :public_key)").unwrap();
        //conn.exec_drop(&stmt, params! {
          //  "id" => 123,
            //"public_key" => pub_key,
        //}).unwrap();
        //println!("last generated key: {}", conn.last_insert_id())

*/

    
    //设置测试参数
    let secret_key = hex!("66B3790E9CC5B26537FDF6AFA10E6787D2859DB58F5A11DAD0296AD3BD8C222C");
    let public_key = hex!("0105228DED4ED40A0BDA20754F96F4A7A1FE3160D6D1BA3635A0616B0BEC2DB2");
    let message = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let aux_rand = hex!("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let upper_y = hex!("8C4353E191F47E7DB0BADA1263A93235866E16B9932FFB509015238DF4B42705");
    let y = hex!("C9332002ED80FA5012CE38FB34A242EEA366CD023AD1EE4720CF1B1027187214");
    let pre_signature = hex!("
                7CB356FE6D3045A6D3504441310AE549F033E4E76F56344E32BC90065434D8E2
                349CAFC5D611E1E14D52DC561B759BEAA8C01E6921E0AC1AFC047DE59C6B8275
                EBDA403B7B6E0EE38B60E715EE2A6D2D37A0DC625ED4A21747F1BF892D03024D
                C477831453B73D3291ED78FF112BB8038C975F49AF8CC22CB94BA3D51F827A7D");
                //EBDA403B7B6E0EE38B60E715EE2A6D2D37A0DC625ED4A21747F1BF892D03024D");
                
    let signature = hex!("
                7CB356FE6D3045A6D3504441310AE549F033E4E76F56344E32BC90065434D8E2
                EBDA403B7B6E0EE38B60E715EE2A6D2D37A0DC625ED4A21747F1BF892D03024D");
                //FDCFCFC8C392DC31602115515017DED94C26EB6B5CB29A621CD398F5C383F489");

    let sk = k256::sm2::SigningKey::from_bytes(&secret_key).unwrap();
    let pk = k256::sm2::VerifyingKey::from_bytes(&public_key).unwrap();

    //预签名生成，传入私钥，message，随机数，困难关系状态Y
    let pre_test = k256::sm2::SigningKey::try_pre_sign_prehashed(&sk, &message, &aux_rand, &upper_y).unwrap();
    let pre_test_hex = hex::encode_upper(pre_test);
    println!("预签名值为{:#?}\n",pre_test_hex);

    //预签名验证，传入公钥，消息，预签名
    let valid = k256::sm2::VerifyingKey::verify_pre_prehashed(&pk, &message, &pre_signature).is_ok();
    if valid == true {
        println!("预签名验证:此预签名有效\n");
    } else {
        println!("预签名验证:此预签名无效\n");
    }

    //适配算法，传入y和预签名
    let sign_test = k256::sm2::SigningKey::try_sign_prehashed(& &pre_signature,  &y).unwrap();
    let sign_test_hex = hex::encode_upper(sign_test);
    println!("签名值为{:#?}\n",sign_test_hex);
 
    //验证签名是否有效
    let valid = k256::sm2::VerifyingKey::verify_sign(&pk, &message, &signature).is_ok();
    if valid == true {
        println!("签名验证:此签名有效\n");
    } else {
        println!("签名验证:此签名无效\n");
    }

    //提取算法，传入预签名和正式签名
    let y_test = k256::sm2::SigningKey::try_extract_y(&pre_signature, &signature);

    let y_test_hex = hex::encode_upper(y_test);
    println!("提取y的值为{:#?}\n",y_test_hex);



}
