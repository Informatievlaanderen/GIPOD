# GIPOD
Generiek Informatie Platform Openbaar Domein


## API Documentatie

https://api-gateway.beta.gipod.vlaanderen.be/#/

## Release Notes
https://api-gateway.beta.gipod.vlaanderen.be/#/docs/api/changelog

## Security

Aanvraag van een OAuth client

1.  Registratie organisatie en eigenaar client
De allereerste stap die je moet zetten, is je organisatie registreren bij Informatie Vlaanderen. Neem hiervoor contact op met de Helpdesk van Informatie Vlaanderen.
Wie eigenaar van de client wil zijn, moet zich registreren via https://beta.auth.vlaanderen.be en https://auth.vlaanderen.be

2.   Registratie client    
Neem contact op met Helpdesk Informatie Vlaanderen om je applicatie (client) te registreren. Hiervoor hebben we de volgende gegevens nodig:

* Het gewenste integratiescenario.
Volgende scenario’s zijn mogelijk:
  * Single page webapplication (gebruikersinteractie)
    -> momenteel nog niet gesupporteerd
  * Authorization code grant (zonder gebruikersinteractie):
  Dit scenario is optimaal voor klanten die veel klanten hebben die toegang willen tot de API. Maak je een client voor een klant? Dan moet deze klant een mail sturen naar het Geosecure-team dat jouw client calls mag doen voor je klant. Je klant zal dan een service account krijgen die gekoppeld is aan je client.  Geef duidelijk het emailadres en de naam van de organisatie mee waar deze service account aan gelinkt is.
  -> momenteel nog niet gesupporteerd
  *	Client credentials grant (zonder gebruikersinteractie): 
  Dit scenario kan alleen gebruikt worden door klanten die in het bezit zijn van de Client Secret en waarbij de eigenaar van de client dezelfde is als de klant zelf.  Wil je een client aanmaken voor een andere organisatie dan de jouwe, dan kijk je best naar B2B met Authorizationcode. (methode voor de nieuwe GIPOD)

* De naam van de organisatie en e-mailadres waaraan de service account gelinkt is in geval van Authorization code grant en Client Credentials grant.
* De naam van de client
* De eigenaar van de client (de persoon die binnen je organisatie verantwoordelijk is voor de client, deze persoon moet geregistreerd zijn in Geosecure);
* Een tekstuele omschrijving van de client
* Een redirect uri
* De scopes die je wil aanvragen.
  * scope = gipod_read

3.  Na registratie van de client: Je kan nu een authorizationcode genereren via de website beta.oauth.vlaanderen.be of oauth.vlaanderen.be
Met die code een accesstoken vragen zoals beschreven op https://oauth.vlaanderen.be/authorization/Help.
Het bekomen accesstoken gebruiken om de call te doen.

## Support

Tijdens de ontwikkeling worden alle vragen, suggesties , bugs behandeled door het GIPOD project-team. Deze kunnen als issues ingebracht worden in de de GIPOD GitHub repository van Agentschap Informatie Vlaanderen.

Tijdens de productie fase zal de dan geldende support flow binnen Informatie Vlaanderen van toepassing worden.

## Disclaimer

Tijdens de ontwikkelingsfase bieden wij geen garanties naar beschikbaarheid van de service en data, performantie, antwoordtijden op vragen.
