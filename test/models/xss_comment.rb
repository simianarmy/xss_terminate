# Comment uses the default: stripping tags from all fields before validation
class XssComment < ActiveRecord::Base
  belongs_to :entry
  belongs_to :person
  validates_presence_of :title
end