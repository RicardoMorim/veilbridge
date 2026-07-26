# Regulatory context

Status checked: 2026-07-26  
This document is technical context, not legal advice.

## EU online child sexual abuse proposals

The long-term EU proposal commonly called “Chat Control” is procedure
`2022/0155(COD)`. As of this review, the Council and European Parliament are
still negotiating the permanent framework.

On 23 July 2026, the Council gave final approval to a separate temporary measure
allowing providers to resume voluntary detection and removal under an ePrivacy
derogation until 3 April 2028. The Council's announcement says the Parliament's
amendments exclude number-independent interpersonal communications to which
end-to-end encryption is, has been, or will be applied from that temporary
measure. It also says this does not settle the Council's position on the
long-term framework.

Primary sources:

- [Council: temporary measure approved on 23 July 2026](https://www.consilium.europa.eu/da/press/press-releases/2026/07/23/fighting-child-sexual-abuse-online-interim-measure-protecting-children-to-be-reinstated/)
- [Council policy timeline and permanent-framework status](https://www.consilium.europa.eu/en/policies/prevent-child-sexual-abuse-online/)
- [EUR-Lex procedure 2022/0155/COD, political trilogue note](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CONSIL%3AST_6946_2026_INIT)

## Design implications

- The project must not hard-code assumptions about a proposal that is still being
  negotiated.
- The product is a general privacy and endpoint-security tool, not a legal
  “bypass.”
- Whether a future rule applies to this software, its operators, app stores, or
  users requires jurisdiction-specific legal advice at release time.
- Encryption cannot prevent scanning performed by a compromised or mandated
  endpoint before encryption or after decryption.
- Privacy claims and app-store disclosures must describe actual data flows and
  permissions precisely.

## Platform constraints

- Android formally provides `InputMethodService` for custom input methods and
  `NotificationListenerService` for user-authorised notification observation.
- Apple documents that custom keyboards are sandboxed by default; enabling open
  access expands capabilities and privacy responsibilities. Keyboard extensions
  also have functional restrictions and cannot be treated as universal
  background interceptors.

Primary sources:

- [Android InputMethodService](https://developer.android.com/reference/android/inputmethodservice/InputMethodService)
- [Android NotificationListenerService](https://developer.android.com/reference/android/service/notification/NotificationListenerService)
- [Apple Custom Keyboard extension guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/CustomKeyboard.html)

Platform behavior and store policies are release-time dependencies and must be
revalidated before each mobile release.
