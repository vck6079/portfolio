create or replace package xxber_aws_auth_pkg
as
/*
  Purpose:   PL/SQL wrapper package for Amazon AWS authentication API

  Remarks:  inspired by the whitepaper "Building an Amazon S3 Client with Application Express 4.0" 
            by Jason Straub
            (http://jastraub.blogspot.com/2011/01/building-amazon-s3-client-with.html).

            Modified and rewritten completely by VKalyani to support "AWS Signature Version 4" 
            API signature calculations, see 
            https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html for more details.
            Adopted for xxber's use.

            dependencies: owner of this package needs execute on dbms_crypto

  Who       Date        Description
  ------    ----------  -------------------------------------
  MBR       09.01.2011  Created
  VKalyani  29.01.2020  Rewrote to support AWS Signature Version 4 API calculations
*/

  type token_rec is record  (key varchar2(512) ,value varchar2(512));  

  type tokens_tab_typ is table of token_rec index by binary_integer;

  -- get "Authorization" (actually authentication) header string
  function get_ISO8601_date(p_date in date default sysdate) return varchar2;

  function get_ISO8601_datetime(p_datetime in timestamp default systimestamp) 
    return varchar2;
  
  function get_epoch (p_date in date) return number;

  function get_empty_payload_sha256 return varchar2 deterministic;

  function get_db_charset return varchar2 deterministic;

  function get_hmac_sha256 (p_key in raw ,p_data in varchar2)
    return varchar2;


  -- generate canonical request hash
  function get_canonical_hash(p_http_verb     in varchar2
                             ,p_resource      in varchar2 default null
                             ,p_payload_hash  in varchar2 default null
                             ,p_query_t       in tokens_tab_typ
                             ,p_headers_t     in tokens_tab_typ
                             )
    return varchar2;

  -- construct the "stringToSign" string
  function get_string_to_sign( p_date            in varchar2
                              ,p_datetime        in varchar2
                              ,p_aws_region      in varchar2 default null
                              ,p_canonical_hash  in varchar2
                             ) 
    return varchar2;

  -- get signature string
  function get_signature(p_string         in varchar2 default null
                        ,p_date           in varchar2 default null
                        ,p_datetime       in varchar2 default null
                        ,p_canonical_hash in varchar2 default null
                        ) return varchar2;

  -- get final authorization string
  function get_auth_string (p_signature in varchar2
                           ,p_date      in varchar2
                           ,p_headers_t in tokens_tab_typ
                           ) 
    return varchar2;


  function get_md5_hash(p_blob in blob) return varchar2;
  
  function get_md5_hash(p_string in varchar2) return varchar2;

  function get_sha256_hash(p_blob in blob) return varchar2;

  function get_sha256_hash(p_string in varchar2) return varchar2;

  -- get AWS access key ID
  function get_aws_id return varchar2;

  -- set AWS access key id
  procedure set_aws_id (p_aws_id in varchar2);

  -- set AWS secret key
  procedure set_aws_key (p_aws_key in varchar2);

  -- set GMT offset
  procedure set_gmt_offset (p_gmt_offset in number);


  procedure force_init ( p_aws_id     in varchar2
                        ,p_aws_key    in varchar2
                        ,p_gmt_offset in number default null
                       );

  -- initialize package for use
  procedure init( p_aws_id      in varchar2
                 ,p_aws_key     in varchar2
                 ,p_gmt_offset  in number default null
                );

end xxber_aws_auth_pkg;
/
sho err
