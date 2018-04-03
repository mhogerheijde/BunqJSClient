export const sessionId = 44;
export const sessionToken =
    "a4f9d888eea84f52722b9baf2f17c289d549edf6e0eccdbf868eb922be306fb6";
export const sessionTokenId = 839;

export default (success = true) => {
    const date = new Date();
    const dateTime = `${date.getFullYear()}-${date.getFullYear()}-${date.getFullYear()} ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}.${date.getMilliseconds()}`;

    return success
        ? {
              status: 200,
              response: {
                  Response: [
                      {
                          Id: {
                              id: sessionId
                          }
                      },
                      {
                          Token: {
                              id: sessionTokenId,
                              token: sessionToken,
                              created: dateTime,
                          }
                      },
                      {
                          UserCompany: {
                              id: 42,
                              created: "2015-06-13 23:19:16.215235",
                              updated: "2015-06-30 09:12:31.981573",
                              public_uuid:
                                  "252e-fb1e-04b74214-b9e9467c3-c6d2fbf",
                              name: "bunq",
                              display_name: "bunq",
                              public_nick_name: "bunq",
                              alias: [
                                  {
                                      type: "EMAIL",
                                      value: "bravo@bunq.com",
                                      name: ""
                                  }
                              ],
                              chamber_of_commerce_number: "NL040492904",
                              type_of_business_entity: "One man business",
                              sector_of_industry: "Education",
                              counter_bank_iban: "NL12BUNQ1234567890",
                              avatar: {
                                  uuid: "5a442bed-3d43-4a85-b532-dbb251052f4a",
                                  anchor_uuid:
                                      "f0de919f-8c36-46ee-acb7-ea9c35c1b231",
                                  image: [
                                      {
                                          attachment_public_uuid:
                                              "d93e07e3-d420-45e5-8684-fc0c09a63686",
                                          content_type: "image/jpeg",
                                          height: 380,
                                          width: 520
                                      }
                                  ]
                              },
                              address_main: {
                                  street: "Example Boulevard",
                                  house_number: "123a",
                                  po_box: "09392",
                                  postal_code: "1234AA",
                                  city: "Amsterdam",
                                  country: "NL"
                              },
                              address_postal: {
                                  street: "Example Boulevard",
                                  house_number: "123a",
                                  po_box: "09392",
                                  postal_code: "1234AA",
                                  city: "Amsterdam",
                                  country: "NL"
                              },
                              version_terms_of_service: "1.2",
                              director_alias: {
                                  uuid: "252e-fb1e-04b74214-b9e9467c3-c6d2fbf",
                                  avatar: {
                                      uuid:
                                          "5a442bed-3d43-4a85-b532-dbb251052f4a",
                                      anchor_uuid:
                                          "f0de919f-8c36-46ee-acb7-ea9c35c1b231",
                                      image: [
                                          {
                                              attachment_public_uuid:
                                                  "d93e07e3-d420-45e5-8684-fc0c09a63686",
                                              content_type: "image/jpeg",
                                              height: 380,
                                              width: 520
                                          }
                                      ]
                                  },
                                  public_nick_name: "Mary",
                                  display_name: "Mary",
                                  country: "NL"
                              },
                              language: "en_US",
                              region: "en_US",
                              ubo: [
                                  {
                                      name: "A. Person",
                                      date_of_birth: "1990-03-27",
                                      nationality: "NL"
                                  }
                              ],
                              status: "ACTIVE",
                              sub_status: "APPROVAL",
                              session_timeout: 1,
                              daily_limit_without_confirmation_login: {
                                  value: "12.50",
                                  currency: "EUR"
                              },
                              notification_filters: [
                                  {
                                      notification_delivery_method: "URL",
                                      notification_target:
                                          "https://my.company.com/callback-url",
                                      category: "PAYMENT"
                                  }
                              ]
                          }
                      }
                  ]
              }
          }
        : {
              status: 500,
              response: { error: "error description" }
          };
};
