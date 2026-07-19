import Foundation

struct PassportData: Equatable {
    var documentNumber: String
    var fullName: String
    var dateOfBirth: String
    var dateOfExpiry: String
    var citizenship: String
    var issuingCountry: String
}
