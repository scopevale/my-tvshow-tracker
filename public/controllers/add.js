angular.module('MyApp')
  .controller('AddCtrl', ['$scope', '$alert', '$http', function($scope, $alert, $http) {
    $scope.addShow = function() {
      $http.post('/api/shows', { showName: $scope.showName })
        .success(function() {
          $scope.showName = '';
          $alert({
            content: 'TV show has been added.',
            placement: 'top-right',
            type: 'success',
            duration: 3
          });
        }),
        .error(function () {
          $alert({
            content: 'TV show not found in TVDB.',
            placement: 'top-right',
            type: 'error',
            duration: 3
          });            
          $scope.showName = '';
        })  
    };
  }]);