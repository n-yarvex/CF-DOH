今天又"端详"了一下[xtlsbbs下的ECH先遣服议题](https://github.com/XTLS/BBS/issues/13)里推的 [Total-ECH](https://github.com/RememberOurPromise/Total-ECH)，哇唔~介个就是某人所谓的"调研1小时,拷打LLM22分钟"后的成果嘛？咱说句不太礼貌的就是如此粗糙的AIslop项目是怎么好意思发出来的捏,就这水平就有自信发新议题整治ygkkk了？笑惹/..

可以对比一下咱的实现,也是滥用CF搭DNS转发器(自用的话应该选择哪个部署连豆包都知道吧,当然也有不足之处就是不支持Meta和优选IP,是因为咱目前还没有这方面需求所以进行的功能取舍),上游是 cloudflare-dns.com ,可以试试：https://doh.nyarvex.top/dns-query ,CF上的域名干干净净地补ECH,其它全部透传。

为什么咱觉得Total-ECH是失败的呢？

首先就是最最讨厌的硬编码,各种硬编码(路径,上游,静态CIDR什么的都懒得多说了),甚至ECH配置都是硬编码在"META_ECH_CONFIG"的(归属meta时直接注入,这是还要用户自己改并且定期更换么说是?)

咱上面说的还不算什么,真正恶心到咱的是那个硬编码的域名列表,Total-ECH把X/Facebook/Instagram/Threads/WhatsApp这种站点写在代码里是什么水平捏?难道RememberOurPromise大佬是意识不到这里应该加个判断逻辑嘛？看看n-yarvex/CF-DOH,收到Type65后先查目标域名的A记录,只要确认IP落在CF官方的CIDR段里就拉 cloudflare-ech.com 的https记录,然后提取alpn+ech就合成应答哦~

中间插一条刚刚发现的,Total甚至连注入路径出问题后的行为都不统一,返回空应答都不算小概率事件,真笑死咱惹,而咱的n-yarvex/CF-DOH都是明确fail-open滴,ECH那边有一旦有任何失败都直接回退到普通DoH转发,至少得保证先能正常解析对吧？

而且咱说你这Total就是个CORS级别的也不过分吧?不然呢(头处理都是能用就行的级别的)?甚至连CORS都应该有最基本的请求体大小限制吖?响应体大小限制吖?超时的硬限制吖?咱还是看 n-yarvex/CF-DOH 吧,请求体上限64KB,响应体上限1MB,上游5秒超时,超限直接返回错误。还有就是n-yarvex/CF-DOH像PATH/DOH/JSON_PATH这种也都是可以通过环境变量配置的,启动的时候都是有校验的,还禁止了凭证/query/fragment/私网,非法配置直接500。哎哟哟,宁说说咱咋就考虑滴这么周到捏?

