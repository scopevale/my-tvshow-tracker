/**
* Created with my-tvshow-tracker.
* User: scopevale
* Date: 2014-06-07
* Time: 09:46 PM
* To change this template use Tools | Templates.
*/
angular.module('MyApp')
  .factory('Show', ['$resource', function($resource) {
    return $resource('/api/shows/:_id');
  }]);