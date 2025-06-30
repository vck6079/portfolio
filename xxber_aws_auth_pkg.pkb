set define off
create or replace package body xxber_aws_auth_pkg
as
/*

  Purpose:  PL/SQL wrapper package for Amazon AWS authentication API
  Remarks:  inspired by the whitepaper "Building an Amazon S3 Client with Application Express 4.0" 
            by Jason Straub
            see http://jastraub.blogspot.com/2011/01/building-amazon-s3-client-with.html
            Modified and rewritten completely by VKalyani to support "AWS Signature Version 4" 
            API signature calculations, see  
            https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html for more details.
            Adopted for xxber's use.             

  Date          Who         Vers.    Description
  ----------    ------      ------   ---------------------------------------------------------------
  09.01.2011    MBR         1.0      Created
  02.07.2020    VKalyani    1.1      Modified and adapted to support AWS Signature Version 4 REST 
                                      API calculations
  */

-- global variables and constants
  g_aws_id                        varchar2(20); -- AWS access key ID
  g_aws_key                       varchar2(40); -- AWS secret key
  g_aws_region                    varchar2(30) := 'us-west-2';
  g_gmt_offset                    number := 4; -- your timezone GMT adjustment 


  --+++---------------------------------------------------------------------+++-
  -- function to date in ISO8601 format
  --+++---------------------------------------------------------------------+++-
  function get_ISO8601_date(p_date in date default sysdate) return varchar2
  is
  begin
    return to_char(sys_extract_utc(p_date),'YYYYMMDD');
  end get_ISO8601_date;


  --+++---------------------------------------------------------------------+++-
  -- function to timestamp in ISO8601 format
  --+++---------------------------------------------------------------------+++-
  function get_ISO8601_datetime(p_datetime in timestamp default systimestamp) return varchar2
  is
  begin
    return replace(to_char(sys_extract_utc(p_datetime),'YYYYMMDD:HH24MISS'),':','T') ||'Z';
  end get_ISO8601_datetime;


  function get_epoch (p_date in date) return number
  is
  begin
    return trunc((p_date - to_date('01-01-1970','MM-DD-YYYY')) * 24 * 60 * 60);
  end get_epoch;  


  --+++---------------------------------------------------------------------+++-
  -- function to get SHA256 of empty string or payload
  --+++---------------------------------------------------------------------+++-
  function get_empty_payload_sha256 
    return varchar2 deterministic 
  is
  begin
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' ;
  end get_empty_payload_sha256;


  function get_db_charset return varchar2 deterministic
  is
  begin
    return 'AL32UTF8';
  end get_db_charset;

  

  function get_hmac_sha256 (p_key in raw ,p_data in varchar2)
    return varchar2
  is
    l_mac_r   raw(2000);
  begin
     l_mac_r := dbms_crypto.mac ( src => utl_i18n.string_to_raw(p_data, get_db_charset),
                                  typ => dbms_crypto.hmac_sh256,
                                  key => p_key
                                );
    return lower(l_mac_r);
  end get_hmac_sha256;  


/*
  -- construct canonical request string and get its hash value
  some rules to achieve UriEncode
  -- URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
  -- The space character is a reserved character and must be encoded as "%20" (and not as "+").
  -- Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
  -- Letters in the hexadecimal value must be uppercase, for example "%1A".
  -- Encode the forward slash character, '/', everywhere except in the object key name. For example, if the 
        object key name is photos/Jan/sample.jpg, the forward slash in the key name is not encoded.  
*/
  function get_canonical_hash(p_http_verb     in varchar2
                             ,p_resource      in varchar2 default null
                             ,p_payload_hash  in varchar2 default null
                             ,p_query_t       in tokens_tab_typ
                             ,p_headers_t     in tokens_tab_typ
                             )
    return varchar2
  is
    l_str           varchar2(32767);
    l_ret           varchar2(64);    
    l_token         varchar2(80);
    l_token_value   varchar2(512);
  begin
    -- http verb
    l_str := nvl(p_http_verb, 'GET')||chr(10);

    -- canonical uri
    l_str := l_str ||utl_url.escape(nvl(p_resource, '/'))||chr(10);

    -- canonical query string
    if p_query_t.count > 0 then

      for x in (select t.* from table(p_query_t) t order by t.key) loop
        -- l_str := l_str ||utl_url.escape(trim(x.key));
        l_str := l_str ||utl_url.escape(trim(x.key))||'=';
        if nvl(trim(x.value),'@@') != '@@' then
          -- l_str := l_str ||'='||utl_url.escape(trim(x.value), true);
          l_str := l_str ||utl_url.escape(trim(x.value), true);
        end if;
        l_str := l_str ||'&';
      end loop;
    end if;
    l_str := rtrim(l_str, '&');
    l_str := l_str ||chr(10);

    --adding canonical headers
    if p_headers_t.count > 0 then
      for y in (select t.* from table(p_headers_t) t order by t.key) loop
        l_str := l_str ||lower(y.key)||':'||trim(y.value)||chr(10);
      end loop;
    end if;
    l_str := l_str ||chr(10);

    -- adding signed headers
    if p_headers_t.count > 0 then
      for y in (select t.* from table(p_headers_t) t order by t.key) loop
        l_str := l_str ||lower(y.key)||';';
      end loop;
      l_str := rtrim(l_str ,';');
    end if;

    -- adding the hashed payload
    l_str := l_str ||chr(10)||nvl(p_payload_hash, get_empty_payload_sha256);

    -- dbms_output.put_line('**---- l_str ----**');
    -- dbms_output.put_line(l_str);
    -- dbms_output.put_line('**---- l_str ----**');

    select standard_hash(l_str, 'SHA256')
      into l_ret
      from dual
    ;
    return lower(l_ret);
  end get_canonical_hash;


  -- construct the "stringToSign" string
  function get_string_to_sign ( p_date            in varchar2
                               ,p_datetime        in varchar2
                               ,p_aws_region      in varchar2
                               ,p_canonical_hash  in varchar2
                              ) 
    return varchar2
  is
  begin
    return 'AWS4-HMAC-SHA256'||chr(10)|| p_datetime||chr(10)||
            p_date||'/'||nvl(p_aws_region, g_aws_region)||'/s3/aws4_request'||chr(10)||
            p_canonical_hash
            ;
  end get_string_to_sign;


  /*
    Purpose:   get signature part of authentication string
    Remarks:   
    Who     Date        Description
    ------  ----------  -------------------------------------
    MBR     09.01.2011  Created  
  */
  function get_signature ( p_string        in varchar2 default null
                          ,p_date           in varchar2 default null
                          ,p_datetime       in varchar2 default null
                          ,p_canonical_hash in varchar2 default null
                          ) return varchar2
  as
    l_string_to_sign            varchar2(1000);
    l_date_key                  raw(2000);
    l_date_region_key           raw(2000);
    l_date_region_service_key   raw(2000);
    l_signing_key               raw(2000);
    l_req_signature             varchar2(64);
  begin
    if p_string is not null then
      l_string_to_sign := p_string;
    else
      --here p_date, p_datetime and p_canonical_hash cannot be null
      l_string_to_sign := get_string_to_sign(p_date           => p_date
                                            ,p_datetime       => p_datetime
                                            ,p_aws_region     => g_aws_region
                                            ,p_canonical_hash => p_canonical_hash
                                            );
    end if;

    l_date_key                := get_hmac_sha256(utl_i18n.string_to_raw('AWS4'||g_aws_key ,get_db_charset)  ,p_date);
    l_date_region_key         := get_hmac_sha256(l_date_key ,g_aws_region);
    l_date_region_service_key := get_hmac_sha256(l_date_region_key ,'s3');
    l_signing_key             := get_hmac_sha256(l_date_region_service_key, 'aws4_request');
    l_req_signature           := get_hmac_sha256(l_signing_key, l_string_to_sign);

    return l_req_signature;
  end get_signature;


  /*
    Purpose:   get authentication string 
    Remarks:   see http://docs.amazonwebservices.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
    Who     Date        Description
    ------  ----------  -------------------------------------
    MBR     09.01.2011  Created  
  */
  function get_auth_string (p_signature in varchar2
                           ,p_date      in varchar2
                           ,p_headers_t in tokens_tab_typ
                           ) 
    return varchar2
  as
   l_auth_str       varchar2(2000);
  begin
    if p_signature is not null then
      l_auth_str := 'AWS4-HMAC-SHA256 Credential='||g_aws_id||'/'
                    ||p_date||'/'||g_aws_region ||'/s3/aws4_request,SignedHeaders=';
                      --host;x-amz-content-sha256;x-amz-date,Signature=
      if p_headers_t.count > 0 then
        for y in (select t.* from table(p_headers_t) t order by t.key) loop
          l_auth_str := l_auth_str ||lower(y.key)||';' ;
        end loop;
        l_auth_str := rtrim(l_auth_str,';');
      end if;

      l_auth_str := l_auth_str||',Signature='||p_signature;
    end if;
    return l_auth_str;
  end get_auth_string;


  --+++---------------------------------------------------------------------+++-
  -- function to generate md5 checksum for a blob
  --+++---------------------------------------------------------------------+++-
  function get_md5_hash(p_blob in blob) return varchar2
  is
    l_raw   raw(2000);
    l_hash  varchar2(64);
  begin
    l_raw := dbms_crypto.hash( src => p_blob
                              ,typ => dbms_crypto.hash_md5
                             );
    l_hash := utl_raw.cast_to_varchar2(utl_encode.base64_encode(l_raw));
    -- return lower(l_raw);
    return l_hash;
  end get_md5_hash;


  --+++---------------------------------------------------------------------+++-
  -- function to generate md5 checksum for a string
  --+++---------------------------------------------------------------------+++-
  function get_md5_hash(p_string in varchar2) return varchar2
  is
    l_raw   raw(2000);
    l_hash  varchar2(64);
  begin
    l_raw := dbms_crypto.hash( src => utl_i18n.string_to_raw(p_string ,get_db_charset)
                              ,typ => dbms_crypto.hash_md5
                             );
    l_hash := utl_raw.cast_to_varchar2(utl_encode.base64_encode(l_raw));
    -- return lower(l_raw);
    return l_hash;
  end get_md5_hash;


  --+++---------------------------------------------------------------------+++-
  -- function to generate SHA256 hash for a blob
  --+++---------------------------------------------------------------------+++-
  function get_sha256_hash(p_blob in blob) return varchar2
  is
  begin
    return lower(dbms_crypto.hash( src => p_blob
                                  ,typ => dbms_crypto.hash_sh256));

  end get_sha256_hash;


  --+++---------------------------------------------------------------------+++-
  -- function to generate SHA256 hash for a string
  --+++---------------------------------------------------------------------+++-
  function get_sha256_hash(p_string in varchar2) return varchar2
  is
  begin
    return lower(dbms_crypto.hash( src => utl_i18n.string_to_raw(p_string ,get_db_charset)
                                  ,typ => dbms_crypto.hash_sh256));

  end get_sha256_hash;


  /*
    Purpose:   get AWS access k ID
    Remarks:   

    Who     Date        Description
    ------  ----------  -------------------------------------  
    MBR     09.01.2011  Created
  */
  function get_aws_id return varchar2
  is
  begin
    return g_aws_id;
  end get_aws_id;


  /*
    Purpose:   set AWS access key id
    Remarks:   
    Who     Date        Description
    ------  ----------  -------------------------------------
    MBR     18.01.2011  Created  
  */
  procedure set_aws_id (p_aws_id in varchar2)
  is
  begin
    g_aws_id := p_aws_id;
  end set_aws_id;


  /*
    Purpose:   set AWS secret key
    Remarks:   
    Who     Date        Description
    ------  ----------  -------------------------------------
    MBR     18.01.2011  Created  
  */
  procedure set_aws_key (p_aws_key in varchar2)
  is
  begin
    g_aws_key := p_aws_key;
  end set_aws_key;


  /*
    Purpose:   set GMT offset
    Remarks:   
    Who     Date        Description
    ------  ----------  -------------------------------------
    MBR     03.03.2011  Created  
  */
  procedure set_gmt_offset (p_gmt_offset in number)
  is
  begin
    g_gmt_offset := p_gmt_offset;
  end set_gmt_offset;


  /*
    Purpose:   initialize package for use
    Remarks:   
    Who     Date        Description
    ------  ----------  -------------------------------------
    MBR     03.03.2011  Created  
  */
  procedure force_init ( p_aws_id     in varchar2
                        ,p_aws_key    in varchar2
                        ,p_gmt_offset in number
                       )
  is
  begin
    g_aws_id := p_aws_id;
    g_aws_key := p_aws_key;
    g_gmt_offset := nvl(p_gmt_offset, g_gmt_offset);
  end force_init;


  procedure init ( p_aws_id in varchar2
                  ,p_aws_key in varchar2
                  ,p_gmt_offset in number
                 )
  is
  begin
    if g_aws_id is null then
      g_aws_id := p_aws_id;
    end if;

    if g_aws_key is null then
      g_aws_key := p_aws_key;
    end if;
    g_gmt_offset := nvl(p_gmt_offset, g_gmt_offset);
  end init;  

end xxber_aws_auth_pkg;
/
sho err
