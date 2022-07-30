"use strict";(self.webpackChunknew_docs=self.webpackChunknew_docs||[]).push([[5991],{3905:function(e,n,t){t.d(n,{Zo:function(){return p},kt:function(){return f}});var r=t(7294);function o(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function i(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);n&&(r=r.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,r)}return t}function a(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?i(Object(t),!0).forEach((function(n){o(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):i(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function l(e,n){if(null==e)return{};var t,r,o=function(e,n){if(null==e)return{};var t,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||(o[t]=e[t]);return o}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)t=i[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(o[t]=e[t])}return o}var s=r.createContext({}),u=function(e){var n=r.useContext(s),t=n;return e&&(t="function"==typeof e?e(n):a(a({},n),e)),t},p=function(e){var n=u(e.components);return r.createElement(s.Provider,{value:n},e.children)},d={inlineCode:"code",wrapper:function(e){var n=e.children;return r.createElement(r.Fragment,{},n)}},c=r.forwardRef((function(e,n){var t=e.components,o=e.mdxType,i=e.originalType,s=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),c=u(t),f=o,g=c["".concat(s,".").concat(f)]||c[f]||d[f]||i;return t?r.createElement(g,a(a({ref:n},p),{},{components:t})):r.createElement(g,a({ref:n},p))}));function f(e,n){var t=arguments,o=n&&n.mdxType;if("string"==typeof e||o){var i=t.length,a=new Array(i);a[0]=c;var l={};for(var s in n)hasOwnProperty.call(n,s)&&(l[s]=n[s]);l.originalType=e,l.mdxType="string"==typeof e?e:o,a[1]=l;for(var u=2;u<i;u++)a[u]=t[u];return r.createElement.apply(null,a)}return r.createElement.apply(null,t)}c.displayName="MDXCreateElement"},3883:function(e,n,t){t.r(n),t.d(n,{assets:function(){return p},contentTitle:function(){return s},default:function(){return f},frontMatter:function(){return l},metadata:function(){return u},toc:function(){return d}});var r=t(7462),o=t(3366),i=(t(7294),t(3905)),a=["components"],l={title:"Upgrade",sidebar_position:3},s=void 0,u={unversionedId:"administer/upgrade",id:"administer/upgrade",title:"Upgrade",description:"Upgrading Firezone will disconnect all VPN sessions and require shutting",source:"@site/docs/administer/upgrade.md",sourceDirName:"administer",slug:"/administer/upgrade",permalink:"/administer/upgrade",draft:!1,editUrl:"https://github.com/firezone/firezone/docs/administer/upgrade.md",tags:[],version:"current",sidebarPosition:3,frontMatter:{title:"Upgrade",sidebar_position:3},sidebar:"tutorialSidebar",previous:{title:"Manage Installation",permalink:"/administer/manage"},next:{title:"Uninstall",permalink:"/administer/uninstall"}},p={},d=[{value:"Upgrading from &lt; 0.5.0 to &gt;= 0.5.0",id:"upgrading-from--050-to--050",level:2},{value:"Bundled Nginx non_ssl_port (HTTP) requests removed",id:"bundled-nginx-non_ssl_port-http-requests-removed",level:3},{value:"ACME protocol support",id:"acme-protocol-support",level:3},{value:"Overlapping egress rule destinations",id:"overlapping-egress-rule-destinations",level:3},{value:"Preconfigured Okta and Google SSO",id:"preconfigured-okta-and-google-sso",level:3},{value:"Existing Google OAuth configuration",id:"existing-google-oauth-configuration",level:4},{value:"Existing Okta OAuth configuration",id:"existing-okta-oauth-configuration",level:4},{value:"Upgrading from 0.3.x to &gt;= 0.3.16",id:"upgrading-from-03x-to--0316",level:2},{value:"I have an existing OIDC integration",id:"i-have-an-existing-oidc-integration",level:3},{value:"I have an existing OAuth integration",id:"i-have-an-existing-oauth-integration",level:3},{value:"I have not integrated an identity provider",id:"i-have-not-integrated-an-identity-provider",level:3},{value:"Upgrading from 0.3.1 to &gt;= 0.3.2",id:"upgrading-from-031-to--032",level:2},{value:"Upgrading from 0.2.x to 0.3.x",id:"upgrading-from-02x-to-03x",level:2},{value:"Upgrading from 0.1.x to 0.2.x",id:"upgrading-from-01x-to-02x",level:2}],c={toc:d};function f(e){var n=e.components,t=(0,o.Z)(e,a);return(0,i.kt)("wrapper",(0,r.Z)({},c,t,{components:n,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Upgrading Firezone will disconnect all VPN sessions and require shutting\ndown the Web UI. We recommend a maintenance window of about an hour in case\nanything goes wrong during the upgrade."),(0,i.kt)("p",null,"To upgrade Firezone, follow these steps:"),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"If not setup already, install our package repository based on your distro's\npackage format:",(0,i.kt)("ul",{parentName:"li"},(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://cloudsmith.io/~firezone/repos/firezone/setup/#formats-deb"},"deb packages")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://cloudsmith.io/~firezone/repos/firezone/setup/#formats-rpm"},"rpm packages")))),(0,i.kt)("li",{parentName:"ol"},"Upgrade the ",(0,i.kt)("inlineCode",{parentName:"li"},"firezone")," package using your distro's package manager."),(0,i.kt)("li",{parentName:"ol"},"Run ",(0,i.kt)("inlineCode",{parentName:"li"},"firezone-ctl reconfigure")," to pick up the new changes."),(0,i.kt)("li",{parentName:"ol"},"Run ",(0,i.kt)("inlineCode",{parentName:"li"},"firezone-ctl restart")," to restart services.")),(0,i.kt)("p",null,"Occasionally problems arise. If you hit any, please let us know by ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/firezone/firezone/issues/new/choose"},"filing an\nissue"),"."),(0,i.kt)("h2",{id:"upgrading-from--050-to--050"},"Upgrading from < 0.5.0 to >= 0.5.0"),(0,i.kt)("p",null,"0.5.0 introduces a few breaking changes and configuration updates that will need\nto be addressed. Read more below."),(0,i.kt)("h3",{id:"bundled-nginx-non_ssl_port-http-requests-removed"},"Bundled Nginx non_ssl_port (HTTP) requests removed"),(0,i.kt)("p",null,"0.5.0 and above removes the ",(0,i.kt)("inlineCode",{parentName:"p"},"force_ssl")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"non_ssl_port")," settings for\nNginx. SSL is required for Firezone to function; if you're using (or would like\nto use) your own reverse proxy, we recommend disabling the bundle Nginx service\nby setting ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['nginx']['enabled'] = false")," and pointing your\nreverse proxy directly to the Phoenix app on port 13000 (by default)."),(0,i.kt)("p",null,"Read more about setting up a custom reverse proxy\n",(0,i.kt)("a",{parentName:"p",href:"../deploy/reverse-proxies"},"here"),"."),(0,i.kt)("h3",{id:"acme-protocol-support"},"ACME protocol support"),(0,i.kt)("p",null,"0.5.0 introduces ACME protocol support for automatically renewing SSL\ncertificates with the bundled Nginx service. To enable,"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("p",{parentName:"li"},"Make sure ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['external_url']")," contains a valid FQDN that\nresolves to your server's public IP address.")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("p",{parentName:"li"},"Ensure port ",(0,i.kt)("inlineCode",{parentName:"p"},"80/tcp")," is reachable")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("p",{parentName:"li"},"Enable ACME protocol support with\n",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['ssl']['acme']['enabled'] = true")," in your config file."))),(0,i.kt)("h3",{id:"overlapping-egress-rule-destinations"},"Overlapping egress rule destinations"),(0,i.kt)("p",null,"Firezone 0.5.0 removes the ability to add rules with overlapping destinations.\nWhen upgrading to 0.5.0, our migration script will automatically detect these\ncases and ",(0,i.kt)("strong",{parentName:"p"},"keep only the rules whose destination encompasses the other rule"),".\nIf this is OK, ",(0,i.kt)("strong",{parentName:"p"},"there is nothing you need to do"),"."),(0,i.kt)("p",null,"Otherwise, we recommend modifying your ruleset to eliminate these cases before\nupgrading."),(0,i.kt)("h3",{id:"preconfigured-okta-and-google-sso"},"Preconfigured Okta and Google SSO"),(0,i.kt)("p",null,"Firezone 0.5.0 removes support for the old-style Okta and Google SSO\nconfiguration in favor of the new, more flexible OIDC-based configuration.\nIf you have any configuration under the\n",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['authentication']['okta']")," or\n",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['authentication']['google']")," keys, ",(0,i.kt)("strong",{parentName:"p"},"you need to migrate\nthese to our OIDC-based configuration using the guide below.")),(0,i.kt)("h4",{id:"existing-google-oauth-configuration"},"Existing Google OAuth configuration"),(0,i.kt)("p",null,"Remove these lines containing the old Google OAuth configs from your configuration\nfile located at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-rb"},"default['firezone']['authentication']['google']['enabled']\ndefault['firezone']['authentication']['google']['client_id']\ndefault['firezone']['authentication']['google']['client_secret']\ndefault['firezone']['authentication']['google']['redirect_uri']\n")),(0,i.kt)("p",null,"Then, follow the instructions ",(0,i.kt)("a",{parentName:"p",href:"../authenticate/google"},"here")," to configure Google\nas an OIDC provider."),(0,i.kt)("h4",{id:"existing-okta-oauth-configuration"},"Existing Okta OAuth configuration"),(0,i.kt)("p",null,"Remove these lines containing the old Okta OAuth configs from your configuration\nfile located at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-rb"},"default['firezone']['authentication']['okta']['enabled']\ndefault['firezone']['authentication']['okta']['client_id']\ndefault['firezone']['authentication']['okta']['client_secret']\ndefault['firezone']['authentication']['okta']['site']\n")),(0,i.kt)("p",null,"Then, follow the instructions ",(0,i.kt)("a",{parentName:"p",href:"../authenticate/okta"},"here")," to configure Okta as\nan OIDC provider."),(0,i.kt)("h2",{id:"upgrading-from-03x-to--0316"},"Upgrading from 0.3.x to >= 0.3.16"),(0,i.kt)("p",null,"Follow the instructions below based on your current version and setup:"),(0,i.kt)("h3",{id:"i-have-an-existing-oidc-integration"},"I have an existing OIDC integration"),(0,i.kt)("p",null,"Upgrading to >= 0.3.16 requires the ",(0,i.kt)("inlineCode",{parentName:"p"},"offline_access")," scope for some OIDC providers\nto obtain a refresh token.\nThis ensures Firezone syncs with the identity provider and VPN access is terminated\nonce the user is removed. Previous versions of Firezone do not have this capability.\nUsers who are removed from your identity provider will still have active VPN sessions\nin some cases."),(0,i.kt)("p",null,"For OIDC providers that support the ",(0,i.kt)("inlineCode",{parentName:"p"},"offline_access")," scope, you will need to add\n",(0,i.kt)("inlineCode",{parentName:"p"},"offline_access")," to the ",(0,i.kt)("inlineCode",{parentName:"p"},"scope")," parameter of your OIDC config. The\nFirezone configuration file can be found at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")," and requires\nrunning ",(0,i.kt)("inlineCode",{parentName:"p"},"firezone-ctl reconfigure")," to pick up the changes."),(0,i.kt)("p",null,"If Firezone is able to successfully retrieve the refresh token, you will see\nthe ",(0,i.kt)("strong",{parentName:"p"},"OIDC Connections")," heading in the user details page of the web UI for\nusers authenticated through your OIDC provider."),(0,i.kt)("p",null,(0,i.kt)("img",{parentName:"p",src:"https://user-images.githubusercontent.com/52545545/173169922-b0e5f2f1-74d5-4313-b839-6a001041c07e.png",alt:"OIDC Connections"})),(0,i.kt)("p",null,"If this does not work, you will need to delete your existing OAuth app\nand repeat the OIDC setup steps to\n",(0,i.kt)("a",{parentName:"p",href:"../authenticate/"},"create a new app integration")," ."),(0,i.kt)("h3",{id:"i-have-an-existing-oauth-integration"},"I have an existing OAuth integration"),(0,i.kt)("p",null,"Prior to 0.3.11, Firezone used pre-configured OAuth2 providers. Follow the\ninstructions ",(0,i.kt)("a",{parentName:"p",href:"../authenticate/"},"here")," to migrate\nto OIDC."),(0,i.kt)("h3",{id:"i-have-not-integrated-an-identity-provider"},"I have not integrated an identity provider"),(0,i.kt)("p",null,"No action needed. You can follow the instructions\n",(0,i.kt)("a",{parentName:"p",href:"../authenticate/"},"here"),"\nto enable SSO through an OIDC provider."),(0,i.kt)("h2",{id:"upgrading-from-031-to--032"},"Upgrading from 0.3.1 to >= 0.3.2"),(0,i.kt)("p",null,"The configuration option ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['fqdn']")," has been removed in favor\nof ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['external_url']"),". Please set this to the\npublicly-accessible URL of your Firezone web portal. If left unspecified it will\ndefault to ",(0,i.kt)("inlineCode",{parentName:"p"},"https://")," + the FQDN of your server."),(0,i.kt)("p",null,"Reminder, the configuration file can be found at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb"),".\nFor an exhaustive list of configuration variables and their descriptions, see the\n",(0,i.kt)("a",{parentName:"p",href:"../reference/configuration-file"},"configuration file reference"),"."),(0,i.kt)("h2",{id:"upgrading-from-02x-to-03x"},"Upgrading from 0.2.x to 0.3.x"),(0,i.kt)("p",null,"Starting with version 0.3.0, Firezone no longer stores device private\nkeys on the Firezone server. Any existing devices should continue to function\nas-is, but you will not be able to re-download or view these configurations in\nthe Firezone Web UI."),(0,i.kt)("h2",{id:"upgrading-from-01x-to-02x"},"Upgrading from 0.1.x to 0.2.x"),(0,i.kt)("p",null,"Firezone 0.2.x contains some configuration file changes that will need to be\nhandled manually if you're upgrading from 0.1.x. Run the commands below as root\nto perform the needed changes to your ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")," file."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"cp /etc/firezone/firezone.rb /etc/firezone/firezone.rb.bak\nsed -i \"s/\\['enable'\\]/\\['enabled'\\]/\" /etc/firezone/firezone.rb\necho \"default['firezone']['connectivity_checks']['enabled'] = true\" >> /etc/firezone/firezone.rb\necho \"default['firezone']['connectivity_checks']['interval'] = 3_600\" >> /etc/firezone/firezone.rb\nfirezone-ctl reconfigure\nfirezone-ctl restart\n")))}f.isMDXComponent=!0}}]);